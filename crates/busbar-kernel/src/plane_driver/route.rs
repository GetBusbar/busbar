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
    OnPieceIn, OnPieceOut, OutField, RecordWrite, UnitCount, EMIT_DONE, EMIT_TO_FAR_END,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_FIELDS, PIECE_HAS_STATUS, PIECE_LAST,
    VERDICT_RETRY,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{Pass, ReasonCode, Route};
use busbar_contract::plane_calls::{Answered, Lent, PieceInFlight};
use tokio::sync::watch;

use super::cancel::{Buried, CancelBill, Checkpoint};
use super::{blob, BufferCaps, HeadFields, PlaneDriver, UnitState, NO_FIELD, NO_SPAN, ZERO_UNIT};
use crate::teller::UnitCtx;

/// One piece of the far end's reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FarPiece {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// On the reply's first piece: the exact status number and its class.
    pub status: Option<(u32, u32)>,
    /// No piece follows.
    pub last: bool,
    /// The bytes are the far end's fields after its body (trailers): pushed with `PIECE_FIELDS`,
    /// and the plane decides what they mean.
    pub fields: bool,
    /// The walk's own status table (the breaker's `Disposition` of this piece's status) says this
    /// attempt fails over: the pump moves to the next member WITHOUT pushing the piece to the
    /// plane, while no byte has reached the caller.
    pub fail_over: bool,
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
    },
    /// No member is left: the walk's exhaustion terminal, the status the caller is told and its
    /// Retry-After seconds (the floor the walk applies), when it names one.
    Exhausted {
        /// The status number.
        status: u32,
        /// The Retry-After seconds.
        retry_after: Option<u32>,
    },
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
}

/// THE FAR END, as the pump reaches it: the kernel's egress walk and the connector stand behind it
/// in production (member pick, breaker, allow-list, pin, auth fields, the send); a test double in
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
}

/// THE CALLER'S SIDE of the unit: the reply head, then the reply bytes.
pub trait CallerEnd: Sync {
    /// The reply head, once, before the first byte.
    fn head(&self, status: u32, fields: HeadFields);
    /// Write `bytes`, resolving once they are written (the caller's side was writable); `false`
    /// when the caller has gone.
    fn write<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = bool> + Send + 'a;
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
    body: Arc<[u8]>,
    /// The far end's current piece.
    input: Vec<u8>,
    /// The current attempt's member.
    member: Vec<u8>,
    /// The pool the current attempt's member was picked from.
    pool: Vec<u8>,
}

impl PieceBufs {
    pub(crate) fn new(caps: &BufferCaps, body: Arc<[u8]>) -> Self {
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
            ..self
        }
    }
}

/// An `on_piece` frame of `unit` over `bufs`. Built and handed to the dispatcher in one breath, so
/// no raw pointer is ever held across an await. A request unit has no session stream.
fn frame(bufs: &mut PieceBufs, p: &Piece, unit: u64) -> (OnPieceIn, OnPieceOut) {
    let bytes = match p.src {
        Src::Body => &bufs.body[..],
        Src::Input => &bufs.input[..],
        Src::None => &[][..],
    };
    let member = if p.attempt_no == 0 {
        &[][..]
    } else {
        &bufs.member[..]
    };
    let input = OnPieceIn {
        unit,
        from: p.from,
        flags: p.flags,
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
        // The walk's pool is named with its member (K2 fills it from the pick); absent until then.
        pool: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
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
    /// The walk had no member left: its exhaustion terminal's status and Retry-After seconds.
    Exhausted(u32, Option<u32>),
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
    verdict: u32,
    verb: Span,
    target: Span,
    units_needed: u32,
    records_needed: u32,
    fields_needed: u32,
    arena_needed: u64,
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
            verdict: o.verdict,
            verb: o.verb,
            target: o.target,
            units_needed: o.units_needed,
            records_needed: o.records_needed,
            fields_needed: o.fields_needed,
            arena_needed: o.arena_needed,
        }
    }
}

/// Where a piece's emitted bytes go.
enum Toward<'r> {
    FarEnd(&'r mut OutboundRequest),
    Caller,
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
        body: Arc<[u8]>,
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
        self.flight = None;
        (answered, out, cause)
    }

    /// Cancel the unit for `cause` and bill it. With an op that was in flight, its answer carries
    /// the disposition the cancel crossing gave; otherwise the driver makes the ticketless `cancel`
    /// itself, here, on the caller's task.
    pub(crate) fn cancel(&mut self, cause: ReasonCode, done: Option<Answered>) -> CancelBill {
        let disposition = match done.map(|d| (d.disposition, d.outcome)) {
            Some((Some(d), _)) => Some(d),
            Some((None, AbiOutcome::Fault)) => None,
            _ => self.driver.cancel_now(self.ticket),
        };
        let facts = self.lock().facts.clone();
        let bill = CancelBill::new(cause, disposition, &facts);
        self.driver.money.cancelled(self.ctx, &bill);
        bill
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
            Box::new(PieceBufs::new(&BufferCaps::EMPTY, Arc::from(&[][..]))),
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
        let flight = match self.flight.take() {
            Some(mut flight) => match flight.settled() {
                Some(_settled) => None,
                None => {
                    self.driver.calls.drop_client(self.ticket);
                    Some(flight)
                }
            },
            None => None,
        };
        let facts = self.lock().facts.clone();
        self.driver.bury(Buried {
            ctx: self.ctx.clone(),
            ticket: self.ticket,
            facts,
            flight,
        });
    }
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

/// A future that finishes once `left` has passed; never, for `None`.
async fn until(left: Option<Duration>) {
    match left {
        Some(left) => tokio::time::sleep(left).await,
        None => std::future::pending::<()>().await,
    }
}

impl<S, F: FarEnd, C: CallerEnd> super::PlaneUnits<'_, S, F, C> {
    /// S3: every attempt of the unit, until its reply is complete, it fails, or the driver cancels.
    pub(crate) async fn attempts(&self, run: &mut Pumping<'_>) -> End {
        let mut attempt_no = 0;
        'attempt: loop {
            attempt_no += 1;
            let picked = guarded_run(run, self.far.member(run.token, attempt_no)).await;
            let ((member, pool), terminal) = match picked {
                Ok(Pick::Member { name, pool }) => ((name, pool), None),
                Ok(Pick::Exhausted {
                    status,
                    retry_after,
                }) if attempt_no == 1 => ((String::new(), String::new()), Some((status, retry_after))),
                Ok(Pick::Exhausted {
                    status,
                    retry_after,
                }) => return End::Exhausted(status, retry_after),
                Err(cause) => return End::Cancel(cause, None),
            };
            run.bufs.member.clear();
            run.bufs.member.extend_from_slice(member.as_bytes());
            run.bufs.pool.clear();
            run.bufs.pool.extend_from_slice(pool.as_bytes());
            let far_bound = !member.is_empty();
            let mut request = OutboundRequest {
                member,
                pool,
                attempt_no,
                ..OutboundRequest::default()
            };
            // THE ATTEMPT PIECE, then the caller's body the kernel kept, re-pushed on every attempt.
            // With no member for the first attempt there is no ATTEMPT piece: the body alone, which
            // a plane may answer itself (a local answer); otherwise the unit has nowhere to go.
            let attempt = Piece {
                from: FROM_KERNEL,
                flags: 0,
                status: (0, 0),
                attempt_no,
                src: Src::None,
            };
            let body = Piece {
                from: FROM_CALLER,
                flags: PIECE_LAST,
                attempt_no: 0,
                src: Src::Body,
                ..attempt
            };
            let pieces: &[Piece] = if far_bound { &[attempt, body] } else { &[body] };
            let local = {
                let mut toward = Toward::FarEnd(&mut request);
                for piece in pieces {
                    if let Step::End(end) = self.push(run, *piece, &mut toward).await {
                        return end;
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
                    Some((status, retry_after)) => End::Exhausted(status, retry_after),
                    None => End::Failed(ReasonCode::DestinationUnreachable),
                };
            }
            match guarded_run(run, self.far.send(run.token, request)).await {
                Ok(true) => {}
                // Not sent, so nothing reached the caller: fail over.
                Ok(false) => continue 'attempt,
                Err(cause) => return End::Cancel(cause, None),
            }
            let mut first = true;
            loop {
                let piece = match guarded_run(run, self.far.next(run.token)).await {
                    Ok(Some(piece)) => piece,
                    Ok(None) => FarPiece {
                        last: true,
                        ..FarPiece::default()
                    },
                    Err(cause) => return End::Cancel(cause, None),
                };
                // THE WALK'S OWN STATUS TABLE: an attempt it fails over never reaches the plane,
                // while nothing has reached the caller.
                if piece.fail_over && !run.lock().facts.streamed {
                    continue 'attempt;
                }
                run.lock().facts.far_end_answered = true;
                run.bufs.input.clear();
                run.bufs.input.extend_from_slice(&piece.bytes);
                let status = piece.status.filter(|_| first);
                first = false;
                let far = Piece {
                    from: FROM_FAR_END,
                    flags: if piece.last { PIECE_LAST } else { 0 }
                        | if piece.fields { PIECE_FIELDS } else { 0 }
                        | if status.is_some() {
                            PIECE_HAS_STATUS
                        } else {
                            0
                        },
                    status: status.unwrap_or((0, 0)),
                    attempt_no: 0,
                    src: Src::Input,
                };
                match self.push(run, far, &mut Toward::Caller).await {
                    Step::End(end) => return end,
                    Step::Retry => continue 'attempt,
                    Step::Answered(done) if done || piece.last => return End::Done,
                    Step::Answered(_) => {}
                }
            }
        }
    }

    /// Push one piece: the crossing, the one short re-call, the backpressure loop, the units, and
    /// the delivery of what the plane emitted.
    async fn push(&self, run: &mut Pumping<'_>, mut piece: Piece, toward: &mut Toward<'_>) -> Step {
        loop {
            let (done, out, cause) = run.cross(&piece).await;
            if let Some(cause) = cause {
                return Step::End(End::Cancel(cause, Some(done)));
            }
            let out = match (done.outcome, out) {
                (AbiOutcome::Ready, Some(out)) => out,
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
            let bufs = &run.bufs;
            let units = &bufs.units[..(out.units_written as usize).min(bufs.units.len())];
            let checkpoint = if units.is_empty() {
                Checkpoint::Continue
            } else {
                let mut st = run.lock();
                st.facts.units.clear();
                st.facts.units.extend_from_slice(units);
                drop(st);
                self.driver.money.checkpoint(run.ctx, units)
            };
            let emitted = &bufs.reply[..(out.emitted as usize).min(bufs.reply.len())];
            // A LOCAL ANSWER: the plane answered a piece bound for the far end with its reply done
            // and nothing for the far end. The unit is the plane's to finish: its bytes go to the
            // caller, and no far end is sent to.
            if matches!(toward, Toward::FarEnd(_))
                && out.flags & EMIT_TO_FAR_END == 0
                && out.flags & EMIT_DONE != 0
            {
                *toward = Toward::Caller;
            }
            match toward {
                Toward::FarEnd(request) => {
                    if out.flags & EMIT_TO_FAR_END != 0 {
                        if out.verb.len != 0 {
                            request.verb = bufs.arena(out.verb).to_vec();
                            request.target = bufs.arena(out.target).to_vec();
                        }
                        request.fields.extend(bufs.fields_of(out.fields_written));
                        request.body.extend_from_slice(emitted);
                    }
                }
                Toward::Caller => {
                    let n = emitted.len();
                    let streamed = run.lock().facts.streamed;
                    // A retry verdict fails over only before the first byte; after it, it is hard.
                    if out.verdict == VERDICT_RETRY && !streamed {
                        return Step::Retry;
                    }
                    if !streamed && (out.reply_status != 0 || !emitted.is_empty()) {
                        self.caller
                            .head(out.reply_status, bufs.fields_of(out.fields_written));
                    }
                    if n != 0 {
                        run.lock().facts.streamed = true;
                        let left = run.left();
                        let Pumping { stop, bufs, .. } = &mut *run;
                        let emitted = &bufs.reply[..n];
                        match guarded(stop, left, self.caller.write(emitted)).await {
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
            if out.more == 1 {
                piece = piece.continuation();
                continue;
            }
            return Step::Answered(out.flags & EMIT_DONE != 0);
        }
    }
}
