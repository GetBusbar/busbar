// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome as AbiOutcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    reason_code, FieldList, OnPieceIn, OnPieceOut, OutField, RecordWrite, RefusalCode, UnitCount,
    CLAIM_PROBE, EMIT_DONE, EMIT_FINAL_STATUS, EMIT_MESSAGE_END, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_CUT, PIECE_FIELDS, PIECE_FINAL, PIECE_HAS_STATUS, PIECE_LAST,
    PIECE_OUT_TEXT, PIECE_REFUSED, RECORD_AUDIT, VERDICT_RETRY,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{Pass, ReasonCode, Route};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::plane_calls::{Answered, Lent, PieceInFlight};
use tokio::sync::watch;

use super::cancel::{Buried, CancelBill, Checkpoint};
use super::close::Close;
use super::{blob, BufferCaps, HeadFields, PlaneDriver, UnitState, NO_FIELD, NO_SPAN, ZERO_UNIT};
use crate::host_records::Acked;
use crate::slice::takes_lease;
use crate::teller::UnitCtx;

/// One piece of the far end's reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FarPiece {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// On the reply's first piece: the exact status number and its class. On a trailers piece
    /// (`fields`): the status the transport read off the trailers, where it read one.
    pub status: Option<(u32, u32)>,
    /// No piece follows.
    pub last: bool,
    /// On the reply's first piece: the far end's response head fields the plane's need keeps, in
    /// the far end's order, names lower-case (no other response field crosses).
    pub head: Vec<(Vec<u8>, Vec<u8>)>,
    /// The bytes are the far end's fields after its body (trailers): pushed with `PIECE_FIELDS`,
    /// and the plane decides what they mean.
    pub fields: bool,
    /// The walk's own status table (the breaker's `Disposition` of this piece's status) says this
    /// attempt fails over: the pump moves to the next member WITHOUT pushing the piece to the
    /// plane, while no byte has reached the caller.
    pub fail_over: bool,
    /// On the reply's first piece: the far end relays this answer as the unit's (a terminal's
    /// dispatch: a spill, the least-bad bypass, a queued slot), so it is never failed over: a
    /// retry verdict renders it, as 1.5.5 relayed a degraded dispatch's answer.
    pub relayed: bool,
    /// On the reply's last piece: the answer ended without completing (its connection failed, or
    /// the send's deadline passed, after its head). Pushed with `PIECE_CUT`.
    pub cut: bool,
}

#[must_use]
pub(crate) fn fails_over(streamed: bool, relayed: bool) -> bool {
    !streamed && !relayed
}

#[must_use]
pub(crate) fn far_flags(piece: &FarPiece, has_status: bool, streamed: bool) -> u32 {
    let mut flags = 0;
    if piece.last {
        flags |= PIECE_LAST;
        if piece.cut {
            flags |= PIECE_CUT;
        }
    }
    if piece.fields {
        flags |= PIECE_FIELDS;
    }
    if has_status {
        flags |= PIECE_HAS_STATUS;
        if !fails_over(streamed, piece.relayed) {
            flags |= PIECE_FINAL;
        }
    }
    flags
}

/// What the walk answers for an attempt: the member to try, or the pool's exhaustion terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// The member the walk picked and admitted through its breaker, and the pool it picked it
    /// from (a member shapes its request per pool).
    Member {
        /// The member's configured name.
        name: String,
        /// The pool's configured name.
        pool: String,
        /// Whether the member relays the caller's own credential to the far end (its upstream
        /// credentials are passthrough); the plane is told on every piece from this attempt on.
        passthrough: bool,
        /// The provider the member is served by (the metering row's provider).
        provider: String,
    },
    /// No member is left: the walk's exhaustion terminal, the status the caller is told and its
    /// Retry-After seconds (the floor the walk applies), when it names one.
    Exhausted {
        /// The status number.
        status: u32,
        /// The Retry-After seconds.
        retry_after: Option<u32>,
        /// The terminal's words (`busbar_kernel_egress::wire::Shed::detail`), the previous
        /// release's sentence for that shed.
        detail: &'static str,
    },
    /// The walk refuses for a hook's restriction: a fallback pool no member of which satisfies a
    /// required restrict the hooks decided (the previous release failed closed there rather than
    /// spill to an ineligible far end). The caller is answered as by the hook, with these words.
    Vetoed {
        /// The status number.
        status: u32,
        /// The words.
        text: String,
    },
    /// The walk refuses the unit for `0` before any member was dialled: the member's credential,
    /// re-resolved for this attempt, is unavailable (`ReasonCode::CredentialUnavailable`). The
    /// plane renders the refusal in its own words.
    Refused(ReasonCode),
}

/// One attempt's request, as the plane bound it for the far end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundRequest {
    /// The member the walk picked.
    pub member: String,
    /// The pool the walk picked it from.
    pub pool: String,
    /// The attempt's number, from `1`.
    pub attempt_no: u32,
    /// The verb.
    pub verb: Vec<u8>,
    /// The target.
    pub target: Vec<u8>,
    /// The dialect's head fields (the kernel adds the auth fields when it sends).
    pub fields: HeadFields,
    /// The body.
    pub body: Vec<u8>,
    /// The need the request rides, as the plane named it (`OnPieceOut::need`: its declared index
    /// plus one); `0` = the member's own.
    pub need: u32,
    /// The plane marked the request's message text (`PIECE_OUT_TEXT` on a far-bound answer): a far
    /// end whose wire tells text from binary is written it as text.
    pub text: bool,
}

/// THE FAR END, as the pump reaches it: the kernel's egress walk and the connector stand behind it
/// in production (member pick, breaker, allow-list, pin, auth fields, the send); a test double in
/// THE ROUTE THE KERNEL RESOLVED FOR A UNIT, as its in-session hooks are scoped: the pool label its
/// walk runs under (empty for a direct route, as 1.5.5 labelled it) and the container its entry's
/// hooks are filed under (a pool route's label, or the direct route's entry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutedScope {
    /// The pool label (routed-order planes: the global and this pool's hooks).
    pub pool: String,
    /// The container (gate-first planes: the hooks attached to this entry).
    pub container: String,
}

pub trait FarEnd: Sync {
    fn member<'a>(
        &'a self,
        token: &'a Pass<Route>,
        attempt_no: u32,
    ) -> impl Future<Output = Pick> + Send + 'a;

    fn send<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a;

    fn next<'a>(
        &'a self,
        token: &'a Pass<Route>,
    ) -> impl Future<Output = Option<FarPiece>> + Send + 'a;

    fn remaining(&self, token: &Pass<Route>) -> Option<usize> {
        let _ = token;
        None
    }

    fn failure(&self, token: &Pass<Route>) -> Option<&'static str> {
        let _ = token;
        None
    }

    fn scope(&self, token: &Pass<Route>) -> Option<RoutedScope> {
        let _ = token;
        None
    }

    fn candidates(&self, token: &Pass<Route>) -> Option<super::hooks::Candidates> {
        let _ = token;
        None
    }

    fn constrain(&self, token: &Pass<Route>, constraint: super::hooks::Constraint) {
        let _ = (token, constraint);
    }

    fn attempt_span(&self, token: &Pass<Route>) -> tracing::Span {
        let _ = token;
        tracing::Span::none()
    }

    fn judged(&self, token: &Pass<Route>, fault: u8) {
        let _ = (token, fault);
    }

    fn taken(&self, token: &Pass<Route>) {
        let _ = token;
    }

    fn judged_stating(&self, token: &Pass<Route>, fault: u8, reason: Option<&str>) {
        let _ = reason;
        self.judged(token, fault);
    }

    fn member_wait(&self, token: &Pass<Route>, member: &str) -> Option<u32> {
        let _ = (token, member);
        None
    }

    fn unsent(&self, token: &Pass<Route>) -> Option<RefusalCode> {
        let _ = token;
        None
    }

    fn stated(&self, token: &Pass<Route>, labels: busbar_kernel_egress::ports::StatedLabels) {
        let _ = (token, labels);
    }

    fn deadline_ns(&self, now_ns: u64) -> u64 {
        let _ = now_ns;
        0
    }

    fn write<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a;
}

pub trait CallerEnd: Sync {
    fn head(&self, status: u32, fields: HeadFields);

    fn write<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = bool> + Send + 'a;

    fn write_text<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = bool> + Send + 'a {
        self.write(bytes)
    }

    fn write_piece<'a>(
        &'a self,
        bytes: &'a [u8],
        text: bool,
        message_end: bool,
    ) -> impl Future<Output = bool> + Send + 'a {
        let _ = message_end;
        async move {
            if bytes.is_empty() {
                true
            } else if text {
                self.write_text(bytes).await
            } else {
                self.write(bytes).await
            }
        }
    }

    fn final_status(&self, status: u32, message: &[u8], details: &[u8]) {
        let _ = (status, message, details);
    }
}

pub(crate) struct PieceBufs {
    reply: Vec<u8>,

    window: usize,
    units: Vec<UnitCount>,
    records: Vec<RecordWrite>,
    fields: Vec<OutField>,
    arena: Vec<u8>,

    body: bytes::Bytes,

    input: SessionInput,

    member: Vec<u8>,

    pool: Vec<u8>,

    resolved: Vec<u8>,

    provider: String,

    pub(crate) claim: u32,

    pub(crate) dialect: u32,

    pub(crate) caller_ref: Vec<u8>,

    stream: u64,

    head: FieldList,

    pub(crate) passthrough: bool,
}

pub(crate) fn lend_piece(input: &mut SessionInput, piece: &mut FarPiece) {
    *input = SessionInput {
        bytes: std::mem::take(&mut piece.bytes),
        custody: None,
    };
}

impl PieceBufs {
    pub(crate) fn new(caps: &BufferCaps, body: bytes::Bytes) -> Self {
        let mut bufs = PieceBufs {
            reply: vec![0; caps.reply + body.len()],
            window: caps.reply,
            units: Vec::new(),
            records: Vec::new(),
            fields: Vec::new(),
            arena: Vec::new(),
            body,
            input: SessionInput::default(),
            member: Vec::new(),
            pool: Vec::new(),
            resolved: Vec::new(),
            provider: String::new(),
            claim: 0,
            dialect: 0,
            caller_ref: Vec::new(),
            stream: 0,
            head: FieldList::default(),
            passthrough: false,
        };
        bufs.grow(caps.units, caps.records, caps.fields, caps.arena);
        bufs
    }

    fn grow(&mut self, units: usize, records: usize, fields: usize, arena: usize) {
        let record = RecordWrite {
            kind: 0,
            op: 0,
            key: NO_SPAN,
            value: NO_SPAN,
        };
        self.units.resize(units.max(self.units.len()), ZERO_UNIT);
        self.records.resize(records.max(self.records.len()), record);
        self.fields.resize(fields.max(self.fields.len()), NO_FIELD);
        self.arena.resize(arena.max(self.arena.len()), 0);
    }

    fn arena(&self, s: Span) -> &[u8] {
        let start = s.offset as usize;
        self.arena
            .get(start..start.saturating_add(s.len as usize))
            .unwrap_or_default()
    }

    fn fields_of(&self, written: u32) -> HeadFields {
        self.fields
            .iter()
            .take(written as usize)
            .map(|f| (self.arena(f.name).to_vec(), self.arena(f.value).to_vec()))
            .collect()
    }
}

/// Where a piece's bytes come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Src {
    None,
    Body,
    Input,
}

/// One piece to push.
#[derive(Debug, Clone, Copy)]
struct Piece {
    from: u32,
    flags: u32,
    status: (u32, u32),
    attempt_no: u32,
    src: Src,
    /// The piece lends the far end's kept response head fields.
    head: bool,
    /// With `PIECE_REFUSED`: the refusal's reason code (`OnPieceIn::reason`); `0` otherwise.
    reason: u32,
}

impl Piece {
    fn continuation(self) -> Self {
        Piece {
            flags: 0,
            status: (0, 0),
            attempt_no: 0,
            src: Src::None,
            head: false,
            reason: 0,
            ..self
        }
    }
}

pub(super) fn operator_name(key: &[u8]) -> &[u8] {
    let sep = crate::governance::PLANE_LANE_SEP as u8;
    key.iter()
        .position(|b| *b == sep)
        .map_or(key, |at| &key[at + 1..])
}

fn frame(bufs: &mut PieceBufs, p: &Piece, unit: u64) -> (OnPieceIn, OnPieceOut) {
    let bytes = match p.src {
        Src::Body => &bufs.body[..],
        Src::Input => &bufs.input.bytes[..],
        Src::None => &[][..],
    };
    let (member, pool) = if p.attempt_no == 0 {
        (&bufs.resolved[..], &[][..])
    } else {
        (operator_name(&bufs.member), operator_name(&bufs.pool))
    };
    let str_of = |b: &[u8]| {
        if b.is_empty() {
            AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            }
        } else {
            AbiStr {
                ptr: b.as_ptr(),
                len: b.len(),
            }
        }
    };
    let input = OnPieceIn {
        unit,
        from: p.from,
        flags: p.flags,
        stream: bufs.stream,
        bytes: blob(bytes),
        status_code: p.status.0,
        status_class: p.status.1,
        reply_buf: bufs.reply.as_mut_ptr(),
        reply_cap: if p.from == FROM_CALLER {
            bufs.reply.len()
        } else {
            bufs.window
        },
        units_buf: bufs.units.as_mut_ptr(),
        units_cap: bufs.units.len(),
        records_buf: bufs.records.as_mut_ptr(),
        records_cap: bufs.records.len(),
        fields_buf: bufs.fields.as_mut_ptr(),
        fields_cap: bufs.fields.len(),
        arena_buf: bufs.arena.as_mut_ptr(),
        arena_cap: bufs.arena.len(),
        member: AbiStr::over(member),
        attempt_no: p.attempt_no,

        pool: str_of(pool),
        caller_ref: str_of(&bufs.caller_ref),
        claim: bufs.claim,
        dialect: bufs.dialect,
        head_fields: if p.head {
            bufs.head.as_ptr()
        } else {
            std::ptr::null()
        },
        head_fields_len: if p.head { bufs.head.len() } else { 0 },
        passthrough: u32::from(bufs.passthrough),
        reason: p.reason,
        ..blank_in()
    };
    (input, blank_out())
}

pub(crate) enum End {
    Done,

    Failed(ReasonCode),

    Exhausted(u32, Option<u32>, &'static str),

    Vetoed(u32, String),

    Cancel(ReasonCode, Option<Answered>),
}

enum Step {
    Answered(bool),

    Retry,

    End(End),
}

/// The scalars of a READY `on_piece` answer the pump reads (the `out` itself carries the plugin's
/// envelope pointers and is not held across an await).
#[derive(Debug, Clone, Copy)]
struct Answer {
    emitted: u64,
    more: u32,
    flags: u32,
    reply_status: u32,
    fields_written: u32,
    units_written: u32,
    records_written: u32,
    verdict: u32,
    /// The plane's breaker fault reading of a far-end answer (`FAULT_*`).
    fault: u8,
    verb: Span,
    target: Span,
    need: u32,
    lane: Span,
    units_needed: u32,
    records_needed: u32,
    fields_needed: u32,
    arena_needed: u64,
    final_status: u32,
    final_message: Span,
    final_details: Span,
    metric_pool: Span,
    metric_lane: Span,
    wait_member: Span,
    tap_fault: u8,
    /// The reason the plane's fault reading states.
    fault_reason: Span,
}

impl Answer {
    fn of(o: &OnPieceOut) -> Self {
        Answer {
            emitted: o.emitted,
            more: o.more,
            flags: o.flags,
            reply_status: o.reply_status,
            fields_written: o.fields_written,
            units_written: o.units_written,
            records_written: o.records_written,
            verdict: o.verdict,
            fault: o.fault,
            verb: o.verb,
            target: o.target,
            need: o.need,
            lane: o.lane,
            units_needed: o.units_needed,
            records_needed: o.records_needed,
            fields_needed: o.fields_needed,
            arena_needed: o.arena_needed,
            final_status: o.final_status,
            final_message: o.final_message,
            final_details: o.final_details,
            metric_pool: o.metric_pool,
            metric_lane: o.metric_lane,
            wait_member: o.wait_member,
            tap_fault: o.tap_fault,
            fault_reason: o.fault_reason,
        }
    }

    fn says_done(&self, piece: &Piece, final_answer: bool) -> bool {
        closes_unit(
            self.flags,
            self.more,
            self.verdict,
            piece.flags,
            final_answer,
        )
    }

    fn usage_tap_fault(&self) -> Option<&'static str> {
        busbar_contract::codec::UsageTapFault::reason_of(self.tap_fault)
    }
}

enum Toward<'r> {
    FarEnd(&'r mut OutboundRequest),
    Caller,

    Session(&'r mut OutboundRequest),

    Nowhere,
}

type Keep = Arc<Mutex<Option<Box<PieceBufs>>>>;

pub(crate) struct Pumping<'u> {
    driver: &'u PlaneDriver,
    token: &'u Pass<Route>,
    state: &'u Mutex<UnitState>,
    ctx: &'u UnitCtx,
    ticket: Ticket,
    deadline_ns: u64,
    stop: watch::Receiver<bool>,
    bufs: Box<PieceBufs>,
    keep: Keep,
    flight: Option<Box<dyn PieceInFlight>>,

    closing: Option<super::cancel::CancelFuture>,
    // Each side of a session owns its ticket's terminal answer or cancellation. The shared
    // unit close state still closes the logical unit and the shared bill remains exactly once.
    closed: bool,
    ended: bool,

    cancel_writes: Vec<busbar_contract::plane_calls::CancelWrite>,

    wait_member: Option<String>,

    piece_flags: u32,

    final_answer: bool,
}

impl<'u> Pumping<'u> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        driver: &'u PlaneDriver,
        token: &'u Pass<Route>,
        state: &'u Mutex<UnitState>,
        ctx: &'u UnitCtx,
        ticket: Ticket,
        deadline_ns: u64,
        body: bytes::Bytes,
    ) -> Self {
        driver.calls.bind_unit(ticket, ctx.key.get());
        Pumping {
            driver,
            token,
            state,
            ctx,
            ticket,
            deadline_ns,
            stop: driver.reload.subscribe(),
            bufs: Box::new(PieceBufs::new(&driver.config.caps, body)),
            keep: Arc::new(Mutex::new(None)),
            flight: None,
            closing: None,
            closed: false,
            ended: false,
            cancel_writes: Vec::new(),
            wait_member: None,
            piece_flags: 0,
            final_answer: false,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, UnitState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn left(&self) -> Option<Duration> {
        (self.deadline_ns != 0).then(|| {
            Duration::from_nanos(self.deadline_ns.saturating_sub(self.driver.calls.now_ns()))
        })
    }

    async fn cross(&mut self, p: &Piece) -> (Answered, Option<Answer>, Option<ReasonCode>) {
        self.piece_flags = p.flags;

        if p.from == FROM_KERNEL && p.attempt_no > 0 {
            self.final_answer = false;
        }
        if p.head {
            self.final_answer = p.flags & PIECE_FINAL != 0;
        }
        let calls = &self.driver.calls;
        let (input, out) = frame(&mut self.bufs, p, self.ctx.key.get());
        let left = self.left();
        let lent: Lent = self.keep.clone();
        let flight = self
            .flight
            .insert(calls.on_piece(self.ticket, input, out, lent));
        let (answered, cause) = match guarded(&mut self.stop, left, &mut **flight).await {
            Ok(answered) => (answered, None),
            Err(cause) => {
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .cancel_started
                    .store(true, std::sync::atomic::Ordering::Release);
                calls.drop_client(self.ticket);
                ((&mut **flight).await, Some(cause))
            }
        };
        let out = flight.out().map(|o| Answer::of(&o));

        if cause.is_some() {
            self.cancel_writes = flight.cancel_writes();

            let done = answered.outcome == AbiOutcome::Ready
                && out
                    .as_ref()
                    .is_some_and(|o| o.says_done(p, self.final_answer));
            if answered.disposition.is_some() || answered.outcome == AbiOutcome::Fault || done {
                self.closed = true;
                self.lock().close.closed();
            }
        }
        self.flight = None;
        if answered.outcome == AbiOutcome::Ready && p.src == Src::Input {
            self.bufs.input = SessionInput::default();
        }
        (answered, out, cause)
    }

    pub(crate) async fn cancel(&mut self, cause: ReasonCode, done: Option<Answered>) -> CancelBill {
        let observed_terminal = done.is_some();
        let cancelled_result = !self.closed;
        let cancelled = match done.map(|d| (d.disposition, d.outcome)) {
            Some((Some(d), _)) => Some((d, std::mem::take(&mut self.cancel_writes))),
            Some((None, AbiOutcome::Fault)) => None,

            _ if self.closed => None,
            _ => self.cancel_now().await.map(|c| (c.disposition, c.writes)),
        };

        if let Some((_, writes)) = &cancelled {
            let principal = self.lock().principal.clone();
            self.driver.fold_writes(writes, principal.as_ref());
        }
        let disposition = cancelled.map(|(d, _)| d);
        let facts = self.lock().facts.clone();
        let bill = CancelBill::new(cause, disposition, &facts);
        let bill_once = {
            let st = self.lock();
            let result_owned = observed_terminal
                || self.closing.is_some()
                || cancelled_result
                || !st.cancel_started.load(std::sync::atomic::Ordering::Acquire);
            result_owned
                && !st
                    .cancel_billed
                    .swap(true, std::sync::atomic::Ordering::AcqRel)
        };
        if bill_once {
            self.driver.money.cancelled(self.ctx, &bill);
        }
        bill
    }

    pub(crate) async fn cancel_now(&mut self) -> Option<busbar_contract::plane_calls::Cancelled> {
        if self.closed {
            return None;
        }
        self.closed = true;
        {
            let mut st = self.lock();
            st.close.closed();
            st.cancel_started
                .store(true, std::sync::atomic::Ordering::Release);
        }
        self.closing = Some(self.driver.cancel_unit(self.ticket, self.ctx.key.get()));
        let cancelled = self.closing.as_mut().expect("queued cancel").await;
        self.closing = None;
        cancelled
    }

    async fn write_records(&mut self, written: u32) -> Result<(), End> {
        let n = (written as usize).min(self.bufs.records.len());
        if n == 0 {
            return Ok(());
        }
        let refused = || End::Failed(ReasonCode::DurabilityUnavailable);
        let mut acks = Vec::with_capacity(n);
        for w in &self.bufs.records[..n] {
            if w.op == RECORD_AUDIT {
                self.audit(w)?;
                continue;
            }
            let Some((services, caller)) = self.driver.records.as_ref() else {
                return Err(refused());
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            let kind = services.record_kind(caller, w.kind);
            let value = RecordBytes::new(self.bufs.arena(w.value).to_vec());
            let (Some(kind), Ok(value)) = (kind, value) else {
                return Err(refused());
            };
            let acked: Acked = Box::new(move |r| {
                let _ = tx.send(r);
            });
            services
                .record_write(caller, kind.as_str(), self.bufs.arena(w.key), value, acked)
                .map_err(|_| refused())?;
            acks.push(rx);
        }
        for rx in acks {
            match guarded_run(self, rx).await {
                Ok(Ok(Ok(()))) => {}
                Ok(_) => return Err(refused()),
                Err(cause) => return Err(End::Cancel(cause, None)),
            }
        }
        Ok(())
    }

    fn audit(&self, w: &RecordWrite) -> Result<(), End> {
        let principal = self.lock().principal.clone();
        let (key, value) = (self.bufs.arena(w.key), self.bufs.arena(w.value));
        (self.driver)
            .audit_row(w.kind, key, value, principal.as_ref())
            .map_err(|()| End::Failed(ReasonCode::PlanePanic))
    }

    pub(crate) fn lend_unit(&mut self, claim: u32, dialect: u32, caller_ref: &[u8], stream: u64) {
        self.bufs.claim = claim;
        self.bufs.dialect = dialect;
        self.bufs.caller_ref = caller_ref.to_vec();
        self.bufs.stream = stream;
    }

    pub(crate) fn lend_resolved(&mut self, entry: &[u8]) {
        self.bufs.resolved = entry.to_vec();
    }

    fn billed(&self) -> bool {
        takes_lease(self.ctx.origin, self.ctx.kernel_verb_only)
    }

    pub(crate) fn finish(&mut self) {
        self.ended = true;
        self.driver.calls.recycle(self.ticket);
    }
}

impl Drop for Pumping<'_> {
    fn drop(&mut self) {
        let bufs = std::mem::replace(
            &mut self.bufs,
            Box::new(PieceBufs::new(&BufferCaps::EMPTY, bytes::Bytes::new())),
        );
        *self
            .keep
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bufs);
        if self.ended {
            return;
        }

        let (flight, done) = match self.flight.take() {
            Some(mut flight) => match flight.settled() {
                Some(settled) => {
                    let done =
                        answered_done(&settled, &*flight, self.piece_flags, self.final_answer);

                    (Some(flight), done)
                }
                None => {
                    self.lock()
                        .cancel_started
                        .store(true, std::sync::atomic::Ordering::Release);
                    self.driver.calls.drop_client(self.ticket);
                    (Some(flight), false)
                }
            },
            None => (None, false),
        };

        let (facts, principal, closed, billed, started) = {
            let mut st = self.lock();
            let closed = done || self.closed;
            st.close.closed();
            (
                st.facts.clone(),
                st.principal.clone(),
                closed,
                st.cancel_billed.clone(),
                st.cancel_started.clone(),
            )
        };
        self.driver.bury(Buried {
            ctx: self.ctx.clone(),
            ticket: self.ticket,
            facts,
            flight,
            closing: self.closing.take(),
            billed,
            started,
            principal,
            closed,
            piece_flags: self.piece_flags,
            final_answer: self.final_answer,
        });
    }
}

pub(crate) fn closes_unit(
    flags: u32,
    more: u32,
    verdict: u32,
    piece_flags: u32,
    final_answer: bool,
) -> bool {
    flags & EMIT_DONE != 0
        && more == 0
        && piece_flags & PIECE_REFUSED == 0
        && (verdict != VERDICT_RETRY || final_answer)
}

pub(crate) fn answered_done(
    settled: &Answered,
    flight: &dyn PieceInFlight,
    piece_flags: u32,
    final_answer: bool,
) -> bool {
    settled.outcome == AbiOutcome::Ready
        && flight
            .out()
            .is_some_and(|o| closes_unit(o.flags, o.more, o.verdict, piece_flags, final_answer))
}

async fn guarded<T>(
    stop: &mut watch::Receiver<bool>,
    left: Option<Duration>,
    fut: impl Future<Output = T>,
) -> Result<T, ReasonCode> {
    tokio::select! {
        biased;
        v = fut => Ok(v),
        _ = stop.wait_for(|stopped| *stopped) => Err(ReasonCode::Drain),
        () = until(left) => Err(ReasonCode::DeadlineExceeded),
    }
}

async fn guarded_run<T>(
    run: &mut Pumping<'_>,
    fut: impl Future<Output = T>,
) -> Result<T, ReasonCode> {
    let left = run.left();
    guarded(&mut run.stop, left, fut).await
}

async fn turn_wait<T>(
    run: &mut Pumping<'_>,
    turn: Option<&session::Turn<'_>>,
    fut: impl Future<Output = T>,
) -> Result<T, End> {
    let halted = async {
        match turn {
            Some(t) => t.halted().await,
            None => std::future::pending().await,
        }
    };
    let raced = async {
        tokio::select! {
            biased;
            halt = halted => Err(halt),
            v = fut => Ok(v),
        }
    };
    match guarded_run(run, raced).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(halt)) => Err(halt.end()),
        Err(cause) => Err(End::Cancel(cause, None)),
    }
}

async fn until(left: Option<Duration>) {
    match left {
        Some(left) => tokio::time::sleep(left).await,
        None => std::future::pending::<()>().await,
    }
}

pub trait AttemptSteps {
    fn attempting(&self, _ctx: &UnitCtx, _dialect: u32, _provider: &str) {}

    fn usage_tap_fault(&self, _ctx: &UnitCtx, _dialect: u32, _reason: &'static str) {}
}

impl<S: super::DriverSteps> AttemptSteps for S {
    fn attempting(&self, ctx: &UnitCtx, dialect: u32, provider: &str) {
        super::DriverSteps::attempting(self, ctx, dialect, provider);
    }
    fn usage_tap_fault(&self, ctx: &UnitCtx, dialect: u32, reason: &'static str) {
        super::DriverSteps::usage_tap_fault(self, ctx, dialect, reason);
    }
}

impl AttemptSteps for () {}

impl<S: AttemptSteps, F: FarEnd, C: CallerEnd> super::PlaneUnits<'_, S, F, C> {
    pub(crate) async fn answered_here(&self, run: &mut Pumping<'_>) -> End {
        let body = Piece {
            from: FROM_CALLER,
            flags: PIECE_LAST,
            status: (0, 0),
            attempt_no: 0,
            src: Src::Body,
            head: false,
            reason: 0,
        };
        let mut request = OutboundRequest::default();
        let mut toward = Toward::FarEnd(&mut request);
        if let Step::End(end) = self.push(run, body, &mut toward).await {
            return end;
        }
        if matches!(toward, Toward::Caller) {
            End::Done
        } else {
            End::Failed(ReasonCode::DestinationUnreachable)
        }
    }

    pub(crate) async fn attempts(
        &self,
        run: &mut Pumping<'_>,
        turn: Option<&session::Turn<'_>>,
    ) -> End {
        let mut attempt_no = 0;

        let mut failed: Option<&'static str> = None;
        'attempt: loop {
            attempt_no += 1;
            if let Some(t) = turn {
                t.held.send_replace(false);
            }
            let picked = turn_wait(run, turn, self.far.member(run.token, attempt_no)).await;
            let ((member, pool), terminal) = match picked {
                Ok(Pick::Member { name, .. }) if turn.is_some_and(|t| !t.within(&name)) => {
                    continue 'attempt;
                }
                Ok(Pick::Member {
                    name,
                    pool,
                    passthrough,
                    provider,
                }) => {
                    run.bufs.passthrough = passthrough;

                    run.lock().facts.cut = false;
                    self.steps.attempting(run.ctx, run.bufs.dialect, &provider);
                    run.bufs.provider = provider;
                    ((name, pool), None)
                }
                Ok(Pick::Exhausted {
                    status,
                    retry_after,
                    detail,
                }) if attempt_no == 1 => (
                    (String::new(), String::new()),
                    Some((status, retry_after, detail)),
                ),
                Ok(Pick::Exhausted {
                    status,
                    retry_after,
                    detail,
                }) => {
                    let reason = self
                        .far
                        .unsent(run.token)
                        .map_or(reason_code(ReasonCode::BreakerOpen), RefusalCode::code);
                    if let Err(end) = self.refused_piece_coded(run, reason).await {
                        return end;
                    }
                    return match self.stated_wait(run) {
                        Ok(wait) => End::Exhausted(status, wait.or(retry_after), detail),
                        Err(end) => end,
                    };
                }
                Ok(Pick::Vetoed { status, text }) => return End::Vetoed(status, text),
                Ok(Pick::Refused(reason)) => {
                    if reason == ReasonCode::CredentialUnavailable {
                        if let Err(end) = self.refused_piece(run, reason).await {
                            return end;
                        }
                    }
                    return End::Failed(reason);
                }
                Err(end) => return end,
            };
            run.bufs.member.clear();
            run.bufs.member.extend_from_slice(member.as_bytes());
            run.bufs.pool.clear();
            run.bufs.pool.extend_from_slice(pool.as_bytes());
            let far_bound = !member.is_empty();
            if far_bound {
                self.routing_tap(attempt_no, &member, self.far.remaining(run.token), failed);
            }

            let attempt_span = if far_bound {
                self.far.attempt_span(run.token)
            } else {
                tracing::Span::none()
            };
            let mut request = OutboundRequest {
                member,
                pool,
                attempt_no,
                ..turn.map(|t| t.request.clone()).unwrap_or_default()
            };

            let attempt = Piece {
                from: FROM_KERNEL,
                flags: 0,
                status: (0, 0),
                attempt_no,
                src: Src::None,
                head: false,
                reason: 0,
            };
            let body = Piece {
                from: FROM_CALLER,
                flags: PIECE_LAST,
                attempt_no: 0,
                src: Src::Body,
                ..attempt
            };
            let both = [attempt, body];
            let probe = run.bufs.claim == CLAIM_PROBE;
            let pieces: &[Piece] = match (turn.is_some(), far_bound) {
                (true, true) => &both[..1],
                (true, false) => &[],

                (false, true) if probe => &both[..1],
                (false, true) => &both[..],
                (false, false) => &both[1..],
            };
            let local = {
                let mut toward = Toward::FarEnd(&mut request);
                for piece in pieces {
                    match self.push(run, *piece, &mut toward).await {
                        Step::End(end) => return end,

                        Step::Retry if far_bound => continue 'attempt,
                        _ => {}
                    }
                    if matches!(toward, Toward::Caller) {
                        break;
                    }
                }
                matches!(toward, Toward::Caller)
            };
            if local {
                return End::Done;
            }
            if !far_bound {
                return match terminal {
                    Some((status, retry_after, detail)) => {
                        if let Err(end) = self.refused_piece(run, ReasonCode::BreakerOpen).await {
                            return end;
                        }
                        match self.stated_wait(run) {
                            Ok(wait) => End::Exhausted(status, wait.or(retry_after), detail),
                            Err(end) => end,
                        }
                    }
                    None => End::Failed(ReasonCode::DestinationUnreachable),
                };
            }
            let sent = {
                use tracing::Instrument as _;
                self.far
                    .send(run.token, request)
                    .instrument(attempt_span.clone())
            };
            match turn_wait(run, turn, sent).await {
                Ok(true) => {}

                Ok(false) => {
                    failed = self.far.failure(run.token);
                    continue 'attempt;
                }
                Err(end) => return end,
            }
            let mut first = true;
            loop {
                let next = {
                    use tracing::Instrument as _;
                    self.far.next(run.token).instrument(attempt_span.clone())
                };
                let mut piece = match turn_wait(run, turn, next).await {
                    Ok(Some(piece)) => piece,
                    Ok(None) => FarPiece {
                        last: true,
                        ..FarPiece::default()
                    },
                    Err(end) => return end,
                };

                if piece.fail_over && !run.lock().facts.streamed {
                    failed = self.far.failure(run.token);
                    continue 'attempt;
                }
                {
                    let mut facts = run.lock();
                    facts.facts.far_end_answered = true;
                    if first {
                        facts.facts.relayed = piece.relayed;
                    }
                }
                if let Some(t) = turn {
                    t.held.send_replace(true);
                }
                lend_piece(&mut run.bufs.input, &mut piece);

                let head = first && piece.status.is_some();
                let status = piece.status.filter(|_| first || piece.fields);
                if head {
                    run.bufs.head = FieldList::new(piece.head.clone());
                }
                first = false;
                let streamed = {
                    let mut st = run.lock();
                    if piece.last && piece.cut {
                        st.facts.cut = true;
                    }
                    st.facts.streamed
                };
                let far = Piece {
                    from: FROM_FAR_END,
                    flags: far_flags(&piece, status.is_some(), streamed),
                    status: status.unwrap_or((0, 0)),
                    attempt_no: 0,
                    src: Src::Input,
                    head,
                    reason: 0,
                };
                match self.push(run, far, &mut Toward::Caller).await {
                    Step::End(end) => return end,
                    Step::Retry => {
                        failed = self.far.failure(run.token);
                        continue 'attempt;
                    }
                    Step::Answered(done) if done || piece.last => return End::Done,
                    Step::Answered(_) => {}
                }
            }
        }
    }

    async fn refused_piece(&self, run: &mut Pumping<'_>, reason: ReasonCode) -> Result<(), End> {
        self.refused_piece_coded(run, reason_code(reason)).await
    }

    async fn refused_piece_coded(&self, run: &mut Pumping<'_>, reason: u32) -> Result<(), End> {
        run.wait_member = None;
        if self.driver.refused_piece {
            let piece = Piece {
                from: FROM_KERNEL,
                flags: PIECE_REFUSED | PIECE_LAST,
                status: (0, 0),
                attempt_no: 0,
                src: Src::None,
                head: false,
                reason,
            };
            if let Step::End(end) = self.push(run, piece, &mut Toward::Nowhere).await {
                return Err(end);
            }
        }
        Ok(())
    }

    fn stated_wait(&self, run: &mut Pumping<'_>) -> Result<Option<u32>, End> {
        let Some(member) = run.wait_member.take() else {
            return Ok(None);
        };
        match self.far.member_wait(run.token, &member) {
            Some(wait) => Ok(Some(wait)),
            None => Err(End::Failed(ReasonCode::PlanePanic)),
        }
    }

    async fn push(&self, run: &mut Pumping<'_>, mut piece: Piece, toward: &mut Toward<'_>) -> Step {
        let framing = piece.from == FROM_FAR_END
            && (piece.src != Src::Input || run.bufs.input.bytes.is_empty());
        loop {
            let (done, out, cause) = run.cross(&piece).await;
            if let Some(cause) = cause {
                return Step::End(End::Cancel(cause, Some(done)));
            }
            let out = match (done.outcome, out) {
                (AbiOutcome::Ready, Some(out)) => {
                    if out.says_done(&piece, run.final_answer) {
                        run.closed = true;
                        run.lock().close.closed();
                    }
                    out
                }
                (AbiOutcome::Failed, Some(o)) if done.short => {
                    run.bufs.grow(
                        o.units_needed as usize,
                        o.records_needed as usize,
                        o.fields_needed as usize,
                        o.arena_needed as usize,
                    );
                    continue;
                }

                _ => return Step::End(End::Failed(ReasonCode::PlanePanic)),
            };

            if piece.from == FROM_FAR_END {
                let reason = std::str::from_utf8(run.bufs.arena(out.fault_reason))
                    .ok()
                    .filter(|r| !r.is_empty());
                self.far.judged_stating(run.token, out.fault, reason);
                if out.flags & EMIT_DONE != 0 && piece.flags & PIECE_LAST == 0 {
                    self.far.taken(run.token);
                }
            }

            let wait = run.bufs.arena(out.wait_member);
            if !wait.is_empty() {
                let exhausted = piece.from == FROM_KERNEL
                    && piece.flags & PIECE_REFUSED != 0
                    && (piece.reason == reason_code(ReasonCode::BreakerOpen)
                        || RefusalCode::of(piece.reason).is_some_and(RefusalCode::unsent));
                match std::str::from_utf8(wait) {
                    Ok(member) if exhausted => run.wait_member = Some(member.to_string()),
                    _ => return Step::End(End::Failed(ReasonCode::PlanePanic)),
                }
            }

            if piece.from == FROM_KERNEL {
                let word = |s: Span| {
                    std::str::from_utf8(run.bufs.arena(s))
                        .ok()
                        .filter(|w| !w.is_empty())
                        .map(str::to_string)
                };
                let labels = busbar_kernel_egress::ports::StatedLabels {
                    pool: word(out.metric_pool),
                    lane: word(out.metric_lane),
                };
                if labels.pool.is_some() || labels.lane.is_some() {
                    self.far.stated(run.token, labels);
                }
            }

            let lane = run.bufs.arena(out.lane);
            if !lane.is_empty() && run.billed() {
                match std::str::from_utf8(lane) {
                    Ok(lane) => self.driver.money.laned(run.ctx, lane),
                    Err(_) => return Step::End(End::Failed(ReasonCode::PlanePanic)),
                }
            }
            let bufs = &run.bufs;
            let emitted = &bufs.reply[..(out.emitted as usize).min(bufs.reply.len())];
            let caller_bound = match &*toward {
                Toward::Caller => true,
                Toward::Session(_) => out.flags & EMIT_TO_FAR_END == 0,
                Toward::FarEnd(request) => {
                    out.flags & EMIT_TO_FAR_END == 0
                        && (out.flags & EMIT_DONE != 0
                            || (request.member.is_empty()
                                && (out.reply_status != 0 || !emitted.is_empty())))
                }
                Toward::Nowhere => false,
            };
            let commits = {
                let st = run.lock();
                caller_bound
                    && !st.facts.headed
                    && !st.facts.streamed
                    && (out.reply_status != 0 || !emitted.is_empty())
                    && !(out.verdict == VERDICT_RETRY
                        && fails_over(st.facts.streamed, st.facts.relayed))
            };
            if commits && !bufs.member.is_empty() && run.billed() {
                let member = String::from_utf8_lossy(&bufs.member);
                self.driver.money.served(run.ctx, &member, &bufs.provider);
            }
            let units = &bufs.units[..(out.units_written as usize).min(bufs.units.len())];
            let checkpoint = if units.is_empty() || !run.billed() {
                Checkpoint::Continue
            } else {
                let mut st = run.lock();
                st.facts.units.clear();
                st.facts.units.extend_from_slice(units);
                drop(st);
                self.driver.money.checkpoint(run.ctx, units)
            };

            if let Some(reason) = out.usage_tap_fault() {
                self.steps
                    .usage_tap_fault(run.ctx, run.bufs.dialect, reason);
            }
            if let Err(end) = run.write_records(out.records_written).await {
                return Step::End(end);
            }
            let bufs = &run.bufs;
            let emitted = &bufs.reply[..(out.emitted as usize).min(bufs.reply.len())];

            if let Toward::FarEnd(_) = toward {
                if out.verdict == VERDICT_RETRY
                    && out.flags & (EMIT_TO_FAR_END | EMIT_DONE) == 0
                    && out.reply_status == 0
                    && emitted.is_empty()
                {
                    return Step::Retry;
                }
            }

            if let Toward::FarEnd(request) = toward {
                let answered = out.flags & EMIT_DONE != 0
                    || (request.member.is_empty()
                        && (out.reply_status != 0 || !emitted.is_empty()));
                if out.flags & EMIT_TO_FAR_END == 0 && answered {
                    *toward = Toward::Caller;
                }
            }
            let far = match toward {
                Toward::FarEnd(_) => true,
                Toward::Session(_) => out.flags & EMIT_TO_FAR_END != 0,
                Toward::Caller | Toward::Nowhere => false,
            };
            match toward {
                Toward::Nowhere => return Step::Answered(out.flags & EMIT_DONE != 0),
                Toward::FarEnd(request) | Toward::Session(request) if far => {
                    if out.flags & EMIT_TO_FAR_END != 0 {
                        if out.verb.len != 0 {
                            request.verb = bufs.arena(out.verb).to_vec();
                            request.target = bufs.arena(out.target).to_vec();
                        }
                        if out.need != 0 {
                            request.need = out.need;
                        }
                        if out.flags & PIECE_OUT_TEXT != 0 {
                            request.text = true;
                        }
                        request.fields.extend(bufs.fields_of(out.fields_written));
                        request.body.extend_from_slice(emitted);
                    }
                }
                _ => {
                    let n = emitted.len();
                    let (streamed, relayed) = {
                        let held = run.lock();
                        (held.facts.streamed, held.facts.relayed)
                    };

                    if out.verdict == VERDICT_RETRY && fails_over(streamed, relayed) {
                        return Step::Retry;
                    }
                    let headed = run.lock().facts.headed;
                    if !headed && !streamed && (out.reply_status != 0 || !emitted.is_empty()) {
                        {
                            let mut st = run.lock();
                            st.facts.headed = true;
                            st.facts.status = out.reply_status;
                        }

                        let mut fields = bufs.fields_of(out.fields_written);

                        let chosen = self.lock().route_policy.clone();
                        if chosen.is_some() {
                            route_policy_fields(
                                &mut fields,
                                route_policy_headers_enabled(),
                                chosen.as_deref(),
                                &bufs.member,
                            );
                        }
                        self.caller.head(out.reply_status, fields);

                        self.response_tap(false, out.reply_status);
                    }
                    let message_end = out.flags & EMIT_MESSAGE_END != 0;
                    if n != 0 || message_end {
                        if n != 0 {
                            let mut st = run.lock();
                            st.facts.streamed = true;
                            if !framing {
                                st.facts.content = true;
                            }
                        }
                        let left = run.left();
                        let Pumping { stop, bufs, .. } = &mut *run;
                        let emitted = &bufs.reply[..n];
                        let text = out.flags & PIECE_OUT_TEXT != 0;
                        let written = self.caller.write_piece(emitted, text, message_end);
                        match guarded(stop, left, written).await {
                            Ok(true) => {}
                            Ok(false) => {
                                return Step::End(End::Cancel(ReasonCode::ClientGone, None));
                            }
                            Err(cause) => return Step::End(End::Cancel(cause, None)),
                        }
                    }
                }
            }
            if checkpoint == Checkpoint::Cut {
                return Step::End(End::Cancel(ReasonCode::OverBudget, None));
            }

            if out.flags & EMIT_FINAL_STATUS != 0 && out.flags & EMIT_DONE != 0 {
                let bufs = &run.bufs;
                self.caller.final_status(
                    out.final_status,
                    bufs.arena(out.final_message),
                    bufs.arena(out.final_details),
                );
            }
            if out.more == 1 {
                piece = piece.continuation();
                continue;
            }
            return Step::Answered(out.flags & EMIT_DONE != 0);
        }
    }
}

pub const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";

pub const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

static ROUTE_POLICY_HEADERS_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub fn configure_route_policy_headers(enabled: bool) {
    let _ = ROUTE_POLICY_HEADERS_ENABLED.set(enabled);
}

fn route_policy_headers_enabled() -> bool {
    ROUTE_POLICY_HEADERS_ENABLED.get().copied().unwrap_or(false)
}

fn route_policy_fields(
    fields: &mut HeadFields,
    enabled: bool,
    policy: Option<&str>,
    member: &[u8],
) {
    if let Some(name) = policy.filter(|_| enabled && !member.is_empty()) {
        fields.push((
            HDR_ROUTE_POLICY.as_bytes().to_vec(),
            name.as_bytes().to_vec(),
        ));
        fields.push((HDR_ROUTE_TARGET.as_bytes().to_vec(), member.to_vec()));
    }
}

#[path = "session.rs"]
mod session;
pub use session::{SessionCaller, SessionInput};

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/route_tests.rs"]
mod tests;
