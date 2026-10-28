// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE PUMP (`BUSBAR-1.6.0.md` Part 3, §12 "The route pump"): the `on_piece` loop of one
//! unit, run on the caller's runtime task. Every `on_piece` is submitted to the dispatcher on the
//! unit's ticket and its [`Reply`] awaited, so the crossing runs on the ticket's worker and no
//! runtime thread is ever parked (a PENDING answer is simply an await that has not finished).
//!
//! Per attempt: an ATTEMPT piece ([`FROM_KERNEL`], the member, the attempt number), then the
//! caller's body, which the kernel KEPT and re-pushes on every attempt; the plane's answers bound
//! for the far end are gathered into one [`OutboundRequest`] and sent through the [`FarEnd`]. The
//! far end's pieces are pushed [`FROM_FAR_END`] and the plane's emitted bytes go to the caller.
//! A retry verdict fails over only while no byte has reached the caller; after the first byte it
//! is treated as hard. `more = 1` flushes, awaits the caller's side and calls again with an empty
//! piece of the same `from`. A short answer is re-called once with the buffers it named; the dispatcher faults a
//! second short answer. Every READY answer's cumulative units go to the money seam.
//!
//! THE HOST BUFFERS AN OP'S `in` POINTS INTO ([`PieceBufs`]) belong to the unit's pump guard and
//! never move while an op is in flight; a caller that goes away while an op is in flight leaves
//! them buried with that op until it settles. No buffer is ever freed under a crossing.

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

/// WHETHER A RETRY VERDICT FAILS THE ANSWER OVER: only while nothing has streamed to the caller,
/// and never for a relayed answer (a terminal's dispatch). The ONE predicate both the failover
/// verdict and the `PIECE_FINAL` mark read, so the plane is told an answer is final exactly when a
/// retry verdict would not fail it over.
#[must_use]
pub(crate) fn fails_over(streamed: bool, relayed: bool) -> bool {
    !streamed && !relayed
}

/// The flags of a far-end piece as the pump pushes it: its last, cut, trailer and status marks,
/// and, on its first piece, whether a retry verdict would fail it over (`PIECE_FINAL`).
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
    /// end whose wire tells text from binary is written it as text (ARCHITECT Q-L5B-WS-DIAL).
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

/// the driver's own proofs.
pub trait FarEnd: Sync {
    /// The member for attempt `attempt_no` (from `1`), or the walk's exhaustion terminal. May await
    /// (the walk's backoff and queue terminals); the pump bounds it by the unit's deadline.
    ///
    /// Every method is handed the route step's pass, which the walk's breaker records under.
    fn member<'a>(
        &'a self,
        token: &'a Pass<Route>,
        attempt_no: u32,
    ) -> impl Future<Output = Pick> + Send + 'a;
    /// Send one attempt's request; `false` when it could not be sent.
    fn send<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a;
    /// The current attempt's next reply piece; `None` once the reply has ended.
    fn next<'a>(
        &'a self,
        token: &'a Pass<Route>,
    ) -> impl Future<Output = Option<FarPiece>> + Send + 'a;

    /// How many of the pool's candidates the walk has not tried yet, as the `routing` stage tap
    /// tells a hook; `None` when the walk does not say.
    fn remaining(&self, token: &Pass<Route>) -> Option<usize> {
        let _ = token;
        None
    }

    /// Why the attempt that just failed over failed, in the walk's failover vocabulary (the
    /// `routing` stage tap's `previous_failure`); `None` when the walk does not say.
    fn failure(&self, token: &Pass<Route>) -> Option<&'static str> {
        let _ = token;
        None
    }

    /// The route the KERNEL resolved for the unit ([`RoutedScope`]): the scope of its in-session
    /// hook stage (`hook.call`, `content.scan`), so its pool's (or its entry's) own hooks apply to
    /// its sub-operations as they did in 1.5.5. `None` when the far end names none.
    fn scope(&self, token: &Pass<Route>) -> Option<RoutedScope> {
        let _ = token;
        None
    }

    /// The candidates of the pool the walk routes the unit over, as the hooks are shown them;
    /// `None` when the walk names none (the hooks then see no candidate).
    fn candidates(&self, token: &Pass<Route>) -> Option<super::hooks::Candidates> {
        let _ = token;
        None
    }

    /// The hooks' constraint on the walk: the members it may pick, the order it tries them in, and
    /// the restricts a fallback pool's members are held to. Called at most once, before the first
    /// attempt.
    fn constrain(&self, token: &Pass<Route>, constraint: super::hooks::Constraint) {
        let _ = (token, constraint);
    }
    /// THE SPAN OF THE ATTEMPT the walk just took a member for ([`Self::member`]): the attempt's
    /// send and its reply's pieces run inside it, and it closes when the attempt ends or fails
    /// over. The far end decides which attempts open one (status row 173: 1.5.5's `forward_once`
    /// was a terminal's dispatch, `proxy/engine/walk.rs:382`); the default opens none.
    fn attempt_span(&self, token: &Pass<Route>) -> tracing::Span {
        let _ = token;
        tracing::Span::none()
    }
    /// THE PLANE'S FAULT READING of the far end's answer it was just handed: `fault` is the
    /// plane's `OnPieceOut::fault` (`FAULT_NONE` when it states none). The breaker records the
    /// plane's first stated reading of a relayed non-success answer (healthy: a success), the
    /// transport's when the answer's last piece was read with none. The default reads nothing.
    fn judged(&self, token: &Pass<Route>, fault: u8) {
        let _ = (token, fault);
    }
    /// THE PLANE TOOK THE ANSWER AS FINAL before its last piece: it answered the caller itself from
    /// what had arrived (a whole answer past the plane's translation cap is the caller's 500), so
    /// the far end did its work and the attempt's budget unit stays spent, as 1.5.5 kept it for a
    /// body past its cap (its `test_truncated_body_does_not_refund_budget`). A caller that LEAVES
    /// mid-read is not this: no plane answer ends it, and its buffered answer refunds.
    fn taken(&self, token: &Pass<Route>) {
        let _ = token;
    }
    /// [`Self::judged`] with THE REASON THE PLANE'S READING STATES (`OnPieceOut::fault_reason`):
    /// the plane's own neutral words for why it reads the answer so, carried verbatim to the
    /// breaker's record of that reading; `None` = none stated. The kernel never makes its own
    /// from the answer's code. The default records the reading alone.
    fn judged_stating(&self, token: &Pass<Route>, fault: u8, reason: Option<&str>) {
        let _ = reason;
        self.judged(token, fault);
    }
    /// THE WAIT OF ONE MEMBER the plane stated on its answer to the walk's exhausted refused piece
    /// (`OnPieceOut::wait_member`, the entry name as `OnPieceIn::member` lends it): the whole seconds
    /// left on `member`'s cell in the pool the unit's walk routes over (at least 1). `None` when
    /// `member` is no member of that pool, or the far end keeps no walk (the default).
    fn member_wait(&self, token: &Pass<Route>, member: &str) -> Option<u32> {
        let _ = (token, member);
        None
    }

    /// WHY NOTHING LEFT, when no attempt of the walk sent its request: the `Unsent*` code
    /// ([`RefusalCode::unsent`]) of the last attempt's failure before any byte (no route, an
    /// unbound need, a refused target or field name, an unrecordable dispatch, a failed auth call,
    /// a refused open). The walk's exhausted refused piece names it in place of `BreakerOpen`.
    /// `None` once any attempt was sent, or when the far end does not say (the default).
    fn unsent(&self, token: &Pass<Route>) -> Option<RefusalCode> {
        let _ = token;
        None
    }

    /// THE PLANE'S COUNTER LABELS for the attempt its answer to the ATTEMPT piece just made
    /// (`OnPieceOut::metric_pool` / `metric_lane`): the walk's counters take them for this attempt
    /// within their bound. The default takes nothing.
    fn stated(&self, token: &Pass<Route>, labels: busbar_kernel_egress::ports::StatedLabels) {
        let _ = (token, labels);
    }

    /// THE UNIT'S DEADLINE ONCE ITS ROUTE IS KNOWN (ARCHITECT ruling 2026-10-07, STREAM-CEILING),
    /// on the dispatcher's clock (`now_ns` is its reading as the route step starts): the ceiling
    /// the plane states for a streamed answer, which the pump then honours like any deadline, on
    /// the far end's reads and on the caller's writes alike. `0` = none. The default states none.
    fn deadline_ns(&self, now_ns: u64) -> u64 {
        let _ = now_ns;
        0
    }
    /// A HELD FAR END's next frame (a duplex session's: dialled once, by the [`FarEnd::send`] of its
    /// first turn, and held for the session): write `request`'s body, as one message, into the
    /// attempt that send opened and its far end answered. The verb, target and fields were the
    /// open's. `false` when it could not be written (no attempt is held, its answer has ended, or
    /// the far end went away). May await the far end taking the bytes; the session's own waits
    /// bound it.
    fn write<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a;
}

/// THE CALLER'S SIDE of the unit: the reply head, then the reply bytes.
pub trait CallerEnd: Sync {
    /// The reply head, once, before the first byte.
    fn head(&self, status: u32, fields: HeadFields);
    /// Write `bytes`, resolving once they are written (the caller's side was writable); `false`
    /// when the caller has gone.
    fn write<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = bool> + Send + 'a;
    /// Write `bytes` as ONE text message (the plane answered `PIECE_OUT_TEXT`); a caller's side
    /// with no text/binary distinction writes them as any bytes.
    fn write_text<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = bool> + Send + 'a {
        self.write(bytes)
    }
    /// Write `bytes` as `write`/`write_text` do, `message_end` saying they END one message
    /// (`EMIT_MESSAGE_END`: a carrier that frames messages frames one on this boundary, however
    /// many writes its bytes spanned); `bytes` may be empty on a boundary alone. The default has
    /// no messages: it writes the bytes and ignores the boundary.
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
    /// The reply's FINAL status (`EMIT_FINAL_STATUS` on its closing answer), in the numbering the
    /// claim's transport declares, with its message and details bytes: a carrier that reports a
    /// status after the reply's bytes reports this one. The default reports nothing.
    fn final_status(&self, status: u32, message: &[u8], details: &[u8]) {
        let _ = (status, message, details);
    }
}

/// Every host buffer an `on_piece` names, and the bytes it borrows. Owned by the op while it is in
/// flight.
pub(crate) struct PieceBufs {
    reply: Vec<u8>,
    units: Vec<UnitCount>,
    records: Vec<RecordWrite>,
    fields: Vec<OutField>,
    arena: Vec<u8>,
    /// The caller's body, kept for every attempt.
    body: bytes::Bytes,
    /// The far end's current piece.
    input: Vec<u8>,
    /// The current attempt's member.
    member: Vec<u8>,
    /// The pool the current attempt's member was picked from.
    pool: Vec<u8>,
    /// The entry a `ROUTE_SCOPE_LOCAL` unit's scope resolved to, lent as the member of its pieces
    /// with no attempt (empty = none: every other unit).
    resolved: Vec<u8>,
    /// The provider of the current attempt's member.
    provider: String,
    /// The snapshot claim the unit arrived on, lent on every piece.
    pub(crate) claim: u32,
    /// The dialect `arrive` answered, lent on every piece.
    pub(crate) dialect: u32,
    /// The caller's opaque reference, lent on every piece (empty = none).
    pub(crate) caller_ref: Vec<u8>,
    /// A duplex session's stream, lent on every piece (`0` = a request unit).
    stream: u64,
    /// The far end's kept response head fields, lent on the answer's first piece.
    head: FieldList,
    /// Whether the current attempt's member relays the caller's own credential.
    pub(crate) passthrough: bool,
}

/// The far end's piece becomes the input the plane is lent: its bytes are moved, never copied.
pub(crate) fn lend_piece(input: &mut Vec<u8>, piece: &mut FarPiece) {
    *input = std::mem::take(&mut piece.bytes);
}

impl PieceBufs {
    pub(crate) fn new(caps: &BufferCaps, body: bytes::Bytes) -> Self {
        let mut bufs = PieceBufs {
            reply: vec![0; caps.reply],
            units: Vec::new(),
            records: Vec::new(),
            fields: Vec::new(),
            arena: Vec::new(),
            body,
            input: Vec::new(),
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

    /// Make each buffer hold at least what a short answer said it needs.
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
    /// The piece that asks for more output after `more = 1`: the same `from`, no bytes, no flags,
    /// no status (the plane ABI's re-call rule).
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

/// THE OPERATOR'S NAME a plane is lent for the member (and pool) its attempt was picked from
/// (`OnPieceIn::member`, `OnPieceIn::pool`: "the operator's name"): the kernel keys a door plane's
/// walk state by (plane key, entry), written `<plane key>`[`PLANE_LANE_SEP`]`<entry>` (ARCHITECT
/// Q-FL3), and the plane is lent the entry alone, the name its own section writes. A name with no
/// plane key (a model plane's lane) is lent as it is.
///
/// [`PLANE_LANE_SEP`]: crate::governance::PLANE_LANE_SEP
pub(super) fn operator_name(key: &[u8]) -> &[u8] {
    let sep = crate::governance::PLANE_LANE_SEP as u8;
    key.iter()
        .position(|b| *b == sep)
        .map_or(key, |at| &key[at + 1..])
}

/// An `on_piece` frame of `unit` over `bufs`. Built and handed to the dispatcher in one breath, so
/// no raw pointer is ever held across an await.
fn frame(bufs: &mut PieceBufs, p: &Piece, unit: u64) -> (OnPieceIn, OnPieceOut) {
    let bytes = match p.src {
        Src::Body => &bufs.body[..],
        Src::Input => &bufs.input[..],
        Src::None => &[][..],
    };
    let (member, pool) = if p.attempt_no == 0 {
        // A unit answered at its scope's one entry (`ROUTE_SCOPE_LOCAL`) names that entry on the
        // pieces it pushes with no attempt; any other unit names none there.
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
        reply_cap: bufs.reply.len(),
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
        // The walk's pool is named with its member, on an ATTEMPT piece.
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

/// How a unit's pump ended.
pub(crate) enum End {
    /// The reply is complete.
    Done,
    /// The unit failed; nothing was cancelled.
    Failed(ReasonCode),
    /// The walk had no member left: its exhaustion terminal's status, Retry-After seconds and
    /// words.
    Exhausted(u32, Option<u32>, &'static str),
    /// The walk refused for a hook's restriction: the status and the words.
    Vetoed(u32, String),
    /// The driver cancels the unit; the answer of the op that was in flight, if one was.
    Cancel(ReasonCode, Option<Answered>),
}

/// What pushing one piece came to.
enum Step {
    /// The plane answered; `true` = its reply is complete.
    Answered(bool),
    /// A retry verdict before the first byte: fail over.
    Retry,
    /// The unit ends.
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

    /// This answer, to `piece`, is the unit's closing call ([`closes_unit`]); `final_answer` = the
    /// answer's first piece carried `PIECE_FINAL`.
    fn says_done(&self, piece: &Piece, final_answer: bool) -> bool {
        closes_unit(
            self.flags,
            self.more,
            self.verdict,
            piece.flags,
            final_answer,
        )
    }

    /// The usage-tap fault this answer carries, as the reason the kernel counts it under; `None`
    /// only for an answer that carries none. A byte outside the vocabulary is `unknown`, counted.
    fn usage_tap_fault(&self) -> Option<&'static str> {
        busbar_contract::codec::UsageTapFault::reason_of(self.tap_fault)
    }
}

/// Where a piece's emitted bytes go.
enum Toward<'r> {
    FarEnd(&'r mut OutboundRequest),
    Caller,
    /// A duplex session's caller side: an answer bound for the far end ([`EMIT_TO_FAR_END`]) is
    /// gathered as a turn's request; any other goes to the caller.
    Session(&'r mut OutboundRequest),
    /// The refused piece's answer (`PIECE_REFUSED`): its record writes are written and nothing it
    /// emits goes anywhere; the unit's refusal is rendered by `refusal`.
    Nowhere,
}

/// Where a unit's host buffers go when its pump ends: every `on_piece` of the unit lends this
/// ([`Lent`]), so the host holds it for as long as any crossing of the unit is still running. The
/// pump moves its buffers in when it ends; they are freed when the last holder lets go, which is
/// the pump itself when every crossing has returned, and otherwise the crossing the watchdog
/// answered FAULT but could not stop, when it finally returns.
type Keep = Arc<Mutex<Option<Box<PieceBufs>>>>;

/// ONE UNIT'S PUMP: its ticket, its host buffers, the op in flight, and the guard that buries them
/// when the caller goes away. Nothing in its `Drop` crosses the dispatcher: an in-flight op is
/// handed to the client-drop path by message, and a unit with no op in flight is left for the
/// sweep's ticketless `cancel`.
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
    ended: bool,
    /// The record writes the `cancel` that ended the last op carried (SEAM-L(r)).
    cancel_writes: Vec<busbar_contract::plane_calls::CancelWrite>,
    /// The member whose wait the plane stated its refusal answers (`OnPieceOut::wait_member`), on
    /// its answer to the walk's exhausted refused piece.
    wait_member: Option<String>,
    /// The flags of the piece last pushed: the one whose op may still be in flight when the unit
    /// is cut or its caller goes away, so its answer is read against them (a refused piece's done
    /// answer is not the unit's close).
    piece_flags: u32,
    /// The answer being pumped was marked `PIECE_FINAL` on its first piece (the kernel will not
    /// fail it over): a retry verdict on it does not keep the unit ([`closes_unit`]).
    final_answer: bool,
}

impl<'u> Pumping<'u> {
    #[allow(clippy::too_many_arguments)] // the unit's pass beside its six
    pub(crate) fn new(
        driver: &'u PlaneDriver,
        token: &'u Pass<Route>,
        state: &'u Mutex<UnitState>,
        ctx: &'u UnitCtx,
        ticket: Ticket,
        deadline_ns: u64,
        body: bytes::Bytes,
    ) -> Self {
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

    /// How long until the unit's deadline, on the dispatcher's clock; `None` for no deadline.
    fn left(&self) -> Option<Duration> {
        (self.deadline_ns != 0).then(|| {
            Duration::from_nanos(self.deadline_ns.saturating_sub(self.driver.calls.now_ns()))
        })
    }

    /// One `on_piece` crossing on the unit's ticket, on its worker; its answer and the scalars of
    /// its `out`. A deadline or a reload while it is in flight goes to the dispatcher's
    /// client-drop path (the cancel crossing, on the worker) and the op's answer, with its
    /// disposition, is awaited before the pump moves on. The driver keeps the deadline itself;
    /// the dispatcher is handed none, so no second cancel races the driver's.
    async fn cross(&mut self, p: &Piece) -> (Answered, Option<Answer>, Option<ReasonCode>) {
        self.piece_flags = p.flags;
        // THE ANSWER'S FINAL MARK, as the plane is told it: on the answer's head piece alone (a
        // trailer's status is no head, and its `PIECE_FINAL` would be read off a piece the far end
        // never relays), and none yet on a new attempt.
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
                calls.drop_client(self.ticket);
                ((&mut **flight).await, Some(cause))
            }
        };
        let out = flight.out().map(|o| Answer::of(&o));
        // The record writes of a `cancel` that ended it (its client-drop path), for the unit's end.
        if cause.is_some() {
            self.cancel_writes = flight.cancel_writes();
            // THE CANCEL CROSSED ON THE OP'S WORKER (its answer carries the disposition, or the
            // cancel's FAULT): the unit's closing call. So is the op's own answer, when it ended on
            // its own before the cancel reached it saying the unit's reply is complete.
            let done = answered.outcome == AbiOutcome::Ready
                && out
                    .as_ref()
                    .is_some_and(|o| o.says_done(p, self.final_answer));
            if answered.disposition.is_some() || answered.outcome == AbiOutcome::Fault || done {
                self.lock().close.closed();
            }
        }
        self.flight = None;
        (answered, out, cause)
    }

    /// Cancel the unit for `cause` and bill it. With an op that was in flight, its answer carries
    /// the disposition the cancel crossing gave; otherwise the driver makes the ticketless `cancel`
    /// itself, here, on the caller's task.
    pub(crate) fn cancel(&mut self, cause: ReasonCode, done: Option<Answered>) -> CancelBill {
        let cancelled = match done.map(|d| (d.disposition, d.outcome)) {
            Some((Some(d), _)) => Some((d, std::mem::take(&mut self.cancel_writes))),
            Some((None, AbiOutcome::Fault)) => None,
            // ALREADY CLOSED: the op's own done answer beat the cancel to it (`cross` marked it),
            // or the plane said the unit's reply was complete before the cut: a `cancel` now would
            // be its second closing call. It bills as a cancel the plane did not answer.
            _ if self.lock().close == Close::Closed => None,
            _ => self.cancel_now().map(|c| (c.disposition, c.writes)),
        };
        // THE CANCELLED UNIT'S ROW (SEAM-L(r)): what its `cancel` wrote, under its principal.
        if let Some((_, writes)) = &cancelled {
            let principal = self.lock().principal.clone();
            self.driver.fold_writes(writes, principal.as_ref());
        }
        let disposition = cancelled.map(|(d, _)| d);
        let facts = self.lock().facts.clone();
        let bill = CancelBill::new(cause, disposition, &facts);
        self.driver.money.cancelled(self.ctx, &bill);
        bill
    }

    /// The driver's own ticketless `cancel` of the unit, on its ticket and naming it: the unit's
    /// closing call ([`super::close`]).
    pub(crate) fn cancel_now(&self) -> Option<busbar_contract::plane_calls::Cancelled> {
        let cancelled = self.driver.cancel_now(self.ticket, self.ctx.key.get());
        self.lock().close.closed();
        cancelled
    }

    /// THE PIECE'S RECORD WRITES, in the plane's order, through the kernel's one record write path
    /// ([`crate::host_services::KernelServices::record_write`], keyed by the instance). The piece
    /// completes only once the store took every one ([`RecordWrite`]: "a write is DURABLE before
    /// the op that carried it completes ... a write the store refuses fails the op"). An empty
    /// value is a tombstone, written like any value.
    ///
    /// A [`RECORD_AUDIT`] write is the unit's audit row, not a record of the plane's: it is folded
    /// into the kernel's own audit chain ([`super::AuditSink`]) under the unit's principal, in the
    /// plane's order, and needs no record path. An action or resource that is not UTF-8 fails the
    /// unit (a plane fault, never a row the kernel guesses at).
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

    /// THE UNIT'S AUDIT ROW (SEAM-L(k)): a [`RECORD_AUDIT`] write's action (`key`), resource
    /// (`value`) and outcome (`kind`), written on the kernel's audit chain under the principal the
    /// kernel verified for the unit (the plane never sees it; an unverified unit's is anonymous).
    /// The kernel names no record kind: the row's words are the plane's.
    fn audit(&self, w: &RecordWrite) -> Result<(), End> {
        let principal = self.lock().principal.clone();
        let (key, value) = (self.bufs.arena(w.key), self.bufs.arena(w.value));
        (self.driver)
            .audit_row(w.kind, key, value, principal.as_ref())
            .map_err(|()| End::Failed(ReasonCode::PlanePanic))
    }

    /// Lend the unit's own facts on every piece it pushes: the claim it arrived on, the dialect
    /// `arrive` answered, the caller's opaque reference (empty = none) and a session's stream
    /// (`0` = none).
    pub(crate) fn lend_unit(&mut self, claim: u32, dialect: u32, caller_ref: &[u8], stream: u64) {
        self.bufs.claim = claim;
        self.bufs.dialect = dialect;
        self.bufs.caller_ref = caller_ref.to_vec();
        self.bufs.stream = stream;
    }

    /// Lend the entry a `ROUTE_SCOPE_LOCAL` unit's scope resolved to as the member of every piece
    /// it pushes with no attempt (the unit is walked to no member).
    pub(crate) fn lend_resolved(&mut self, entry: &[u8]) {
        self.bufs.resolved = entry.to_vec();
    }

    /// Whether the unit moves money: a tick unit (a health probe) is zero-billed and draws no
    /// lease, §1's exempt origins.
    fn billed(&self) -> bool {
        takes_lease(self.ctx.origin, self.ctx.kernel_verb_only)
    }

    /// The unit reached its end: its ticket goes back.
    pub(crate) fn finish(&mut self) {
        self.ended = true;
        self.driver.calls.recycle(self.ticket);
    }
}

impl Drop for Pumping<'_> {
    fn drop(&mut self) {
        // THE BUFFERS OUTLIVE EVERY CROSSING, not only every answer: they move into the unit's
        // keep, which a crossing still running (one the watchdog answered FAULT, or one the
        // client-drop path is cancelling) holds until it returns.
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
        // THE CALLER WENT AWAY. No crossing here: an op still in flight is handed to the
        // dispatcher's client-drop path by message and buried until it settles; a unit between
        // ops is buried for the sweep's ticketless `cancel`.
        let (flight, done) = match self.flight.take() {
            Some(mut flight) => match flight.settled() {
                // The op ended on its own: its answer may have closed the unit.
                Some(settled) => (
                    None,
                    answered_done(&settled, &*flight, self.piece_flags, self.final_answer),
                ),
                None => {
                    self.driver.calls.drop_client(self.ticket);
                    (Some(flight), false)
                }
            },
            None => (None, false),
        };
        // The buried unit's `cancel` (the client-drop path's, or the sweep's) is its closing call,
        // unless it is closed already: a done answer, or a cancel that crossed before the drop.
        let (facts, principal, closed) = {
            let mut st = self.lock();
            let closed = done || st.close == Close::Closed;
            st.close.closed();
            (st.facts.clone(), st.principal.clone(), closed)
        };
        self.driver.bury(Buried {
            ctx: self.ctx.clone(),
            ticket: self.ticket,
            facts,
            flight,
            principal,
            closed,
            piece_flags: self.piece_flags,
            final_answer: self.final_answer,
        });
    }
}

/// WHETHER AN `on_piece` ANSWER IS THE UNIT'S CLOSING CALL, by the contract's own words: it says
/// "the unit's reply is complete" (`EMIT_DONE`) on its last window (`more == 0`), to a piece that
/// is not the refused piece (`PIECE_REFUSED`: the unit's `refusal` follows it), and it is the
/// unit's last answer: a `VERDICT_RETRY` answer is the unit's last only when its first piece
/// carried `PIECE_FINAL` ("the kernel will not fail this answer over, whatever verdict the plane
/// answers it with, so an answer whose verdict is `VERDICT_RETRY` is the unit's last"). Without
/// it, a plane keeps the unit for the attempt the retry asks for.
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

/// Whether an op that ended on its own (`settled`, its `flight`) closed its unit
/// ([`closes_unit`]), read against the piece it was pushed (`piece_flags`) and its answer's
/// final mark.
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

/// Await `fut`, unless the plane's generation is reloaded or the deadline passes first.
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

/// [`guarded`] over `run`'s reload signal and deadline.
async fn guarded_run<T>(
    run: &mut Pumping<'_>,
    fut: impl Future<Output = T>,
) -> Result<T, ReasonCode> {
    let left = run.left();
    guarded(&mut run.stop, left, fut).await
}

/// [`guarded_run`], and for a session's turn leg also the session's end ([`session::Turn::halted`]):
/// what `fut` answered, or how the walk ends instead. A halt is seen only between crossings, never
/// under one.
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

/// A future that finishes once `left` has passed; never, for `None`.
async fn until(left: Option<Duration>) {
    match left {
        Some(left) => tokio::time::sleep(left).await,
        None => std::future::pending::<()>().await,
    }
}

/// What the attempt loop tells a unit's kernel steps of each attempt: its [`super::DriverSteps`]
/// hook, and nothing for a unit with no steps of its own (a health probe).
pub trait AttemptSteps {
    /// An attempt starts on a member of `provider`, the unit's request read in `dialect`.
    fn attempting(&self, _ctx: &UnitCtx, _dialect: u32, _provider: &str) {}
    /// The plane's answer carried a usage-tap fault of `reason` for the unit read in `dialect`.
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
    /// S3 for a unit its plane answers AT ITS SCOPE'S ONE ENTRY (`ROUTE_SCOPE_LOCAL`): NO route is
    /// walked: the far end is never asked for a member, so no pool, no breaker and no egress is
    /// touched. The caller's body is pushed once, with no attempt (its member the resolved entry,
    /// [`Pumping::lend_resolved`]), and the plane answers it itself; a plane that sends it toward a
    /// far end instead has nowhere to send it, and the unit fails as unreachable.
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

    /// S3: every attempt of the unit, until its reply is complete, it fails, or the driver cancels.
    /// A session's turn leg ([`session::Turn`]) is the same walk: each attempt picks a member
    /// inside the destination set sealed at the open (a member outside it is passed over, never
    /// crossed), pushes only the ATTEMPT piece, and sends the turn's request: the session's ONE dial.
    /// Its far end is then held: the far pieces reach the far side's ticket as they arrive, until
    /// the far end's answer ends or the session does ([`session::Turn::halted`]), and the far end's
    /// first answer tells the session's later turns they may be written into it.
    pub(crate) async fn attempts(
        &self,
        run: &mut Pumping<'_>,
        turn: Option<&session::Turn<'_>>,
    ) -> End {
        let mut attempt_no = 0;
        // Why the previous attempt failed over, for the next attempt's `routing` stage tap.
        let mut failed: Option<&'static str> = None;
        'attempt: loop {
            attempt_no += 1;
            if let Some(t) = turn {
                // A new attempt holds nothing yet: the session's later turns wait for its answer.
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
                    // A new attempt's answer is its own: a cut the walk left behind is not its.
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
                    // The walk's exhaustion terminal is refused as `BreakerOpen` (the route
                    // step's `End::Exhausted`): the refused piece names that reason when a request
                    // went out (R-REJECTED), and when none did, why the last attempt left nothing
                    // on the wire (an `Unsent*` code), so the plane charges no hop that never
                    // left. The unit's end, and the caller's answer, are the same either way.
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
            // THE ATTEMPT'S SPAN, where the far end states one for the member it took (status row
            // 173: a terminal's dispatch opens 1.5.5's `forward_once`, `FarEnd::attempt_span`). It
            // is opened under the unit's request span, its send and its reply's pieces run inside
            // it, and it closes when the attempt ends or fails over.
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
            // THE ATTEMPT PIECE, then the caller's body the kernel kept, re-pushed on every attempt.
            // With no member for the first attempt there is no ATTEMPT piece: the body alone, which
            // a plane may answer itself (a local answer); otherwise the unit has nowhere to go. A
            // health probe has no caller: its ATTEMPT piece alone asks for the probe request.
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
                // A session turn pushes the ATTEMPT piece alone: the turn's request is its body.
                (true, true) => &both[..1],
                (true, false) => &[],
                // A health probe has no caller: its ATTEMPT piece alone asks for the probe request.
                (false, true) if probe => &both[..1],
                (false, true) => &both[..],
                (false, false) => &both[1..],
            };
            let local = {
                let mut toward = Toward::FarEnd(&mut request);
                for piece in pieces {
                    match self.push(run, *piece, &mut toward).await {
                        Step::End(end) => return end,
                        // The plane declined this member: nothing was sent; the next one.
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
                        // THE WALK EXHAUSTED WITH NOTHING SENT (the first attempt found no member):
                        // the refused piece names `BreakerOpen` here too (R-REJECTED, coordinator
                        // 2026-10-07, extends gap-2), so a plane that opens a hop's task can end it.
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
                // Not sent, so nothing reached the caller: fail over.
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
                // THE WALK'S OWN STATUS TABLE: an attempt it fails over never reaches the plane,
                // while nothing has reached the caller.
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
                    // The far end answered this attempt: it is the session's held far end.
                    t.held.send_replace(true);
                }
                lend_piece(&mut run.bufs.input, &mut piece);
                // The status crosses on the answer's first piece, and on its trailers where the
                // transport read one off them (`FarPiece::status`).
                let head = first && piece.status.is_some();
                let status = piece.status.filter(|_| first || piece.fields);
                if head {
                    // THE ANSWER'S HEAD: the kept response fields cross with its first piece.
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

    /// THE REFUSED PIECE, for a plane whose tail states `TAIL_REFUSED_PIECE`: before the unit is
    /// refused for `reason` (its member's credential unavailable before anything was dialled, or
    /// the walk ending with no member left, whether or not a request went out: R-REJECTED, coordinator
    /// 2026-10-07, extends gap-2), the plane is handed the
    /// refusal as a piece first, on the unit's own ticket (`PIECE_REFUSED`, the reason in
    /// `OnPieceIn::reason`): its record writes are written, so the plane changes what it holds
    /// through the host's records as any piece does (a ticketless `refusal` reads none), and
    /// nothing it emits goes anywhere. Then the unit is refused, rendered by `refusal`, as it is
    /// for every other plane; a plane without the bit is sent nothing. `Err` = the unit ended on
    /// the crossing.
    async fn refused_piece(&self, run: &mut Pumping<'_>, reason: ReasonCode) -> Result<(), End> {
        self.refused_piece_coded(run, reason_code(reason)).await
    }

    /// [`Self::refused_piece`] for the wire code `reason` (`OnPieceIn::reason`): a reason's own,
    /// or an `Unsent*` code the walk's exhaustion names when nothing left.
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

    /// THE WAIT A PLANE STATED its walk's exhausted refusal answers (`OnPieceOut::wait_member`, on
    /// the refused piece): that member's own cooldown in the unit's pool, in place of the walk's
    /// soonest across the pool. `Ok(None)` when it stated none (the walk's figure stands); a member
    /// that is no member of the unit's pool is refused, the unit ending as the plane's fault, never
    /// read as none.
    fn stated_wait(&self, run: &mut Pumping<'_>) -> Result<Option<u32>, End> {
        let Some(member) = run.wait_member.take() else {
            return Ok(None);
        };
        match self.far.member_wait(run.token, &member) {
            Some(wait) => Ok(Some(wait)),
            None => Err(End::Failed(ReasonCode::PlanePanic)),
        }
    }

    /// Push one piece: the crossing, the one short re-call, the backpressure loop, the units, and
    /// the delivery of what the plane emitted.
    async fn push(&self, run: &mut Pumping<'_>, mut piece: Piece, toward: &mut Toward<'_>) -> Step {
        // A far-end piece that carries none of the far end's bytes (a cut or a trailer): what the
        // plane writes for it is its own framing, not the answer's content.
        let framing =
            piece.from == FROM_FAR_END && (piece.src != Src::Input || run.bufs.input.is_empty());
        loop {
            let (done, out, cause) = run.cross(&piece).await;
            if let Some(cause) = cause {
                return Step::End(End::Cancel(cause, Some(done)));
            }
            let out = match (done.outcome, out) {
                (AbiOutcome::Ready, Some(out)) => {
                    // THE PLANE SAID THE UNIT'S REPLY IS COMPLETE, and this is its last answer: its
                    // closing call ([`closes_unit`]).
                    if out.says_done(&piece, run.final_answer) {
                        run.lock().close.closed();
                    }
                    out
                }
                (AbiOutcome::Failed, Some(o)) if done.short => {
                    // THE ONE RE-CALL, on the same ticket, with what the answer said it needs; the
                    // dispatcher answers a second short answer FAULT.
                    run.bufs.grow(
                        o.units_needed as usize,
                        o.records_needed as usize,
                        o.fields_needed as usize,
                        o.arena_needed as usize,
                    );
                    continue;
                }
                // A FAULT (the watchdog's, for a crossing that may still be running) ENDS the unit:
                // no `on_piece` may follow a FAULTed one within a unit, because the wedged crossing
                // still holds the unit's buffers. A retry after FAULT would have to lend fresh ones.
                _ => return Step::End(End::Failed(ReasonCode::PlanePanic)),
            };
            // THE PLANE'S FAULT READING of a far-end answer it was handed: recorded against the
            // destination where it states one, the transport's reading otherwise (ARCHITECT
            // 2026-10-05, plane first, then transport). Before the verdict acts, so a retry
            // records the reading of the answer it leaves.
            // The reason the reading states rides with it, verbatim (words that are not UTF-8 are
            // no words, and the reading is recorded with none).
            if piece.from == FROM_FAR_END {
                let reason = std::str::from_utf8(run.bufs.arena(out.fault_reason))
                    .ok()
                    .filter(|r| !r.is_empty());
                self.far.judged_stating(run.token, out.fault, reason);
                if out.flags & EMIT_DONE != 0 && piece.flags & PIECE_LAST == 0 {
                    self.far.taken(run.token);
                }
            }
            // THE MEMBER WHOSE WAIT THE REFUSAL ANSWERS, stated on the answer to the walk's exhausted
            // refused piece and nowhere else (`OnPieceOut::wait_member`): kept for the refusal;
            // stated anywhere else, or not UTF-8, it is the plane's fault, never ignored.
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
            // THE ATTEMPT'S COUNTER LABELS, where the plane's answer to its ATTEMPT piece states
            // them: words for the walk's counters to bound, never to trust (a word that is not
            // UTF-8 is no word, and is stated as none).
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
            let bufs = &run.bufs;
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
            // THE USAGE-TAP FAULT the plane returned beside its units (row 155): counted here, once
            // per answer that carries it (the plane writes it on one window of the answer).
            if let Some(reason) = out.usage_tap_fault() {
                self.steps
                    .usage_tap_fault(run.ctx, run.bufs.dialect, reason);
            }
            // THE UNIT'S LEDGER LANE, where the answer names one (SEAM-L(j)): the money steps
            // lane the unit by it from here. A lane that is not UTF-8 is a plane fault.
            let lane = run.bufs.arena(out.lane);
            if !lane.is_empty() && run.billed() {
                match std::str::from_utf8(lane) {
                    Ok(lane) => self.driver.money.laned(run.ctx, lane),
                    Err(_) => return Step::End(End::Failed(ReasonCode::PlanePanic)),
                }
            }
            if let Err(end) = run.write_records(out.records_written).await {
                return Step::End(end);
            }
            let bufs = &run.bufs;
            let emitted = &bufs.reply[..(out.emitted as usize).min(bufs.reply.len())];
            // A DECLINED MEMBER: the plane answered a piece bound for the far end with nothing at all
            // and the retry verdict (a member this unit may not reach, ARCHITECT round 4
            // Q-L3B-SURFACES (h)): nothing was sent, so the walk moves to its next member.
            if let Toward::FarEnd(_) = toward {
                if out.verdict == VERDICT_RETRY
                    && out.flags & (EMIT_TO_FAR_END | EMIT_DONE) == 0
                    && out.reply_status == 0
                    && emitted.is_empty()
                {
                    return Step::Retry;
                }
            }
            // A LOCAL ANSWER: the plane answered a piece bound for the far end with nothing for the
            // far end, and either its reply done or (with no member to send to) a reply begun: a
            // window of a longer answer asks for more and may not say done (ARCHITECT B7). The unit
            // is the plane's to finish: its bytes go to the caller, and no far end is sent to.
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
                // The refused piece's answer: its record writes are written (above); its output
                // goes nowhere and it bills nothing.
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
                    // A retry verdict fails over only before the first byte; after it, it is hard.
                    // A relayed answer (a terminal's dispatch) is never failed over.
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
                        // THE ANSWER COMMITS: no failover after the first byte, so the member that
                        // answered is the unit's serving member, the one 1.5.5 ledgered and metered
                        // the response under (v1.5.5 `crates/busbar/src/proxy/usage.rs`
                        // `ledger_and_meter`: "`lane` is the SERVING lane"). A local answer has none.
                        if !bufs.member.is_empty() && run.billed() {
                            let model = String::from_utf8_lossy(&bufs.member);
                            self.driver.money.served(run.ctx, &model, &bufs.provider);
                        }
                        let mut fields = bufs.fields_of(out.fields_written);
                        // TRANSPARENCY (opt-in, `advanced.response_headers.route_policy`): which
                        // hook chose the serving member, after the plane's own fields, as 1.5.5
                        // stamped them; nothing on the default path or when no hook chose.
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
                        // The answer's head is the `response` stage (1.5.5 fires it at head time,
                        // a streamed body still flowing).
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
            // THE REPLY'S FINAL STATUS, on its closing answer, for a carrier that reports one after
            // the reply's bytes.
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

/// The `x-busbar-route-policy` transparency response header: the policy that chose the member.
pub const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";
/// The `x-busbar-route-target` transparency response header: the chosen member.
pub const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

static ROUTE_POLICY_HEADERS_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// The operator's `advanced.response_headers.route_policy` opt-in, set once at boot.
pub fn configure_route_policy_headers(enabled: bool) {
    let _ = ROUTE_POLICY_HEADERS_ENABLED.set(enabled);
}

fn route_policy_headers_enabled() -> bool {
    ROUTE_POLICY_HEADERS_ENABLED.get().copied().unwrap_or(false)
}

/// THE ROUTE-POLICY TRANSPARENCY FIELDS (opt-in, `advanced.response_headers.route_policy`), as
/// 1.5.5's `maybe_attach_route_policy_gated` gated them: the pair goes after the plane's own fields
/// only when the operator opted in (`enabled`, the outer gate) AND a non-default policy chose the
/// serving member (`policy`, the inner gate), naming the policy and the member; a local answer
/// (no member) and every other combination add nothing.
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

/// The duplex session's two sides, on this pump (K6): a child module, so it drives the pump's own
/// pieces and push.
#[path = "session.rs"]
mod session;
pub use session::SessionCaller;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/route_tests.rs"]
mod tests;
