// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DRIVER AGAINST A CONTRACT-LEVEL PLANE (`BUSBAR-1.6.0.md` Part 3, §12). The kernel
//! reaches a plane only through the contract's `PlaneCalls`; this double implements it in plain
//! Rust, answering as the composition root's test plane answers (the same member modes, the same
//! counters) and keeping the dispatcher's rules a driver relies on: one re-call of a short answer,
//! a second short answer as FAULT, a pending `on_piece` as a future that the plane's own wake or
//! the client-drop path settles. Every case in `plane_driver_cases.rs` runs against it.

#![allow(unsafe_code, clippy::missing_safety_doc)]

mod common;

#[path = "support/plane_driver_cases.rs"]
mod cases;

#[path = "support/plane_driver_hook_cases.rs"]
mod hook_cases;

#[path = "support/plane_driver_close_cases.rs"]
mod close_cases;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::hook::{MessageView, RequestView};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, ProjectIn, ProjectOut, RecordWrite,
    RefusalIn, RefusalOut, UnitCount, AUDIT_APPLIED, CANCEL_ABORTED, CANCEL_FAILED,
    CANCEL_OK_PARTIAL, EMIT_DONE, EMIT_FINAL_STATUS, EMIT_MESSAGE_END, EMIT_TO_FAR_END,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_FIELDS, PIECE_FINAL, PIECE_HAS_STATUS,
    PIECE_LAST, PIECE_OUT_TEXT, PIECE_REFUSED, PRINCIPAL_OPTIONAL, RECORD_AUDIT, RECORD_PUT,
    REFUSAL_ARRIVE, REFUSED_AFTER_ADMISSION, ROUTE_LOCAL, ROUTE_POOL, ROUTE_SCOPE_LOCAL,
    ROUTE_SESSION, UNITS_ESTIMATED, UNITS_REPORTED, VERDICT_RETRY,
};
use busbar_contract::abi::plane::{ServeIn, ServeOut, REFUSAL_GATE};
use busbar_contract::caps::OpClassId;
use busbar_contract::plane::{TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::{
    Answered, ArrivedTrust, Grow, InstanceDecl, Lent, PieceInFlight, PlaneCalls, ServeInFlight,
};
use busbar_kernel::plane_driver::{refusal_status, BufferCaps, DriverConfig, PlaneDriver};

use cases::stat;

/// The one way this suite reaches a plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Way {
    Double,
}

pub(crate) fn ways() -> Vec<Way> {
    vec![Way::Double]
}

/// The double's clock (the dispatcher's, for a real plane).
pub(crate) fn now_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

pub(crate) struct Rig {
    plane: Arc<Double>,
    pub(crate) driver: PlaneDriver,
    pub(crate) book: Arc<cases::Book>,
}

impl Rig {
    /// Every `project` crossing: the body it was handed and the rewrite, when one came.
    pub(crate) fn projects(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.plane.projects.lock().unwrap().clone()
    }

    pub(crate) fn stats(&self) -> [u64; stat::COUNT] {
        let mut out = [0; stat::COUNT];
        for (k, v) in out.iter_mut().enumerate() {
            *v = self.plane.stats[k].load(Ordering::SeqCst);
        }
        out
    }
}

pub(crate) fn rig(way: Way, caps: BufferCaps, book: cases::Book) -> Rig {
    rig_with_hooks(way, caps, book, None)
}

/// [`rig`], the driver binding `hooks` to each unit.
pub(crate) fn rig_with_hooks(
    _way: Way,
    caps: BufferCaps,
    book: cases::Book,
    hooks: Option<busbar_kernel::plane_driver::BoundHooks>,
) -> Rig {
    let plane = Arc::new(Double::default());
    let book = Arc::new(book);
    let driver = PlaneDriver::new(
        plane.clone(),
        DriverConfig {
            caps,
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses: cases::statuses(),
            caller_refs: None,
        },
        book.clone(),
        services(),
        ("test_plane", &serde_yaml::Value::Null),
    )
    .expect("the instance is admitted");
    let driver = match hooks {
        Some(h) => driver.with_hooks(Arc::new(h)),
        None => driver,
    };
    Rig {
        plane,
        driver,
        book,
    }
}

// ── the double ───────────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Unit {
    mode: Vec<u8>,
    attempt: u32,
    body: Vec<u8>,
    pending: Vec<u8>,
    emitted: u64,
    far_pieces: u32,
    far_answered: bool,
    streamed: bool,
    saw_last: bool,
    pended: bool,
    /// The last answer was short: the next is the one re-call.
    short: bool,
    /// The last answer was `more = 1` from this source: the next piece is its re-call.
    more_from: Option<u32>,
    /// The answer's first piece carried `PIECE_FINAL`: a retry verdict on it does not keep the
    /// unit.
    final_answer: bool,
}

/// One answer, held until it is due. The `out` carries plane pointers; the host reads it only
/// after the answer, on the task that awaits it.
struct Slot {
    answer: Option<(Answered, OnPieceOut)>,
    waker: Option<Waker>,
    /// The record writes the `cancel` that ended the op carried (SEAM-L(r)).
    writes: Vec<busbar_contract::plane_calls::CancelWrite>,
}
struct Shared(Mutex<Slot>);
// SAFETY: the `out` inside is plain data the double wrote; its pointers are never dereferenced.
unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

impl Shared {
    fn put(&self, a: Answered, out: OnPieceOut) {
        let waker = {
            let mut s = self.0.lock().unwrap();
            if s.answer.is_some() {
                return;
            }
            s.answer = Some((a, out));
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

struct Flight(Arc<Shared>);

impl Future for Flight {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answered> {
        let mut s = self.0 .0.lock().unwrap();
        match &s.answer {
            Some((a, _)) => Poll::Ready(*a),
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl PieceInFlight for Flight {
    fn settled(&mut self) -> Option<Answered> {
        self.0 .0.lock().unwrap().answer.map(|(a, _)| a)
    }
    fn out(&self) -> Option<OnPieceOut> {
        self.0 .0.lock().unwrap().answer.map(|(_, o)| o)
    }
    fn cancel_writes(&self) -> Vec<busbar_contract::plane_calls::CancelWrite> {
        self.0 .0.lock().unwrap().writes.clone()
    }
}

#[derive(Default)]
struct Double {
    /// Each unit's state, keyed by the unit's kernel-minted key.
    units: Mutex<HashMap<u64, Unit>>,
    /// The caller's target each unit's `arrive` carried, keyed by `unit`: it crosses once.
    heads: Mutex<HashMap<u64, Vec<u8>>>,
    /// The unit each ticket serves, for `cancel`.
    tickets: Mutex<HashMap<Ticket, u64>>,
    /// The ops held pending, by ticket, and what their `cancel` will answer.
    held: Mutex<HashMap<Ticket, (Arc<Shared>, OnPieceOut)>>,
    next: AtomicU32,
    stats: [AtomicU64; stat::COUNT],
    /// `project` crossings, and the bodies each was handed (with the rewrite, when one came).
    projects: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    /// The driver tickets minted, and every ticket recycled.
    drivers: Mutex<Vec<Ticket>>,
    recycled: Mutex<Vec<Ticket>>,
    /// Each `tick`'s `now_ns`, and the period the next one is asked for (`0` = none).
    ticks: Mutex<Vec<u64>>,
    tick_every_ns: AtomicU64,
    /// Whether it has a wake channel (R-PUSH), and its driver ticket's wakes: a wake has run
    /// `drive`, so the schedule re-polls `tick`.
    wake: Arc<WakeLine>,
    /// What it declares for its admission.
    declared: InstanceDecl,
    /// Its duplex sessions (a `/session` arrival states `ROUTE_SESSION`): see [`Sessions`].
    sessions: Arc<Sessions>,
    /// The reason of every refused piece (`PIECE_REFUSED`) it was handed.
    refused: Mutex<Vec<u32>>,
    /// Every caller piece of a `/scope-local*` unit: its attempt number and the member it lent.
    scope_members: Mutex<Vec<(u32, Vec<u8>)>>,
    /// The caller reference every piece it was handed was lent, in order.
    caller_refs: Mutex<Vec<Vec<u8>>>,
    /// THE CLOSING CALLS each unit had, by its key: an `on_piece` answer that says its reply is
    /// complete (`EMIT_DONE`, its last window), a `refusal` naming it, a `cancel` naming it or the
    /// op it had in flight. A unit is let go at its first; a second finds nothing.
    closes: Mutex<HashMap<u64, u32>>,
}

/// The double's driver-ticket wake line (R-PUSH): off, it has no wake channel.
#[derive(Default)]
struct WakeLine {
    channel: AtomicBool,
    told: tokio::sync::Notify,
}

/// The double's sessions: the streams open, the caller pieces each read (stream, bytes), the
/// collections answered, and the streams `drive` names once a tick owes them output.
#[derive(Default)]
struct Sessions {
    open: Mutex<Vec<u64>>,
    read: Mutex<Vec<(u64, Vec<u8>)>>,
    collects: AtomicU64,
    named: Mutex<Vec<u64>>,
    told: tokio::sync::Notify,
}
// SAFETY: the held `out`s are plain data the double wrote.
unsafe impl Send for Double {}
unsafe impl Sync for Double {}

fn ready(outcome: Outcome) -> Answered {
    Answered {
        outcome,
        short: false,
        disposition: None,
    }
}

unsafe fn bytes<'a>(b: Blob) -> &'a [u8] {
    if b.ptr.is_null() || b.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(b.ptr, b.len)
    }
}

/// What the double answers a refused piece with: never the caller's.
const NOT_FOR_THE_CALLER: &[u8] = b"not-for-the-caller";

/// The words the double's `/refuse-words` arrival states for its refusal.
const REFUSAL_WORDS: &[u8] = b"the body is not a document";

/// The plane's own code and status for the double's refusals about an entry (`/refuse-entry`).
const ENTRY_REFUSED: u32 = 11;
const ENTRY_REFUSED_STATUS: u32 = 409;

unsafe fn text<'a>(s: AbiStr) -> &'a [u8] {
    if s.ptr.is_null() || s.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(s.ptr, s.len)
    }
}

unsafe fn put(i: &OnPieceIn, at: &mut usize, b: &[u8]) -> Span {
    std::ptr::copy_nonoverlapping(b.as_ptr(), i.arena_buf.add(*at), b.len());
    let span = Span {
        offset: *at as u32,
        len: b.len() as u32,
    };
    *at += b.len();
    span
}

impl Double {
    fn count(&self, k: usize) {
        self.stats[k].fetch_add(1, Ordering::SeqCst);
    }

    /// A closing call for `unit` crossed.
    fn closed(&self, unit: u64) {
        *self.closes.lock().unwrap().entry(unit).or_default() += 1;
    }

    /// The state of the unit `ticket` serves, removed.
    fn unit_of(&self, ticket: Ticket) -> Unit {
        let unit = self.tickets.lock().unwrap().remove(&ticket);
        unit.and_then(|k| self.units.lock().unwrap().remove(&k))
            .unwrap_or_default()
    }

    /// The disposition `cancel` answers for `u`; `None` = FAULT.
    /// What a `cancel` of `u` writes: a `hang-row` unit writes its audit row, `thing.cancel` on
    /// `thing:x` applied (SEAM-L(r)); any other writes nothing.
    fn cancel_row(&self, u: &Unit) -> Vec<busbar_contract::plane_calls::CancelWrite> {
        if u.mode != b"hang-row" {
            return Vec::new();
        }
        vec![busbar_contract::plane_calls::CancelWrite {
            kind: AUDIT_APPLIED,
            op: RECORD_AUDIT,
            key: b"thing.cancel".to_vec(),
            value: b"thing:x".to_vec(),
        }]
    }

    fn disposition(&self, u: &Unit) -> Option<u32> {
        let d = if u.mode == b"cancel-fault" {
            None
        } else if u.streamed {
            Some(CANCEL_OK_PARTIAL)
        } else if u.far_answered {
            Some(CANCEL_FAILED)
        } else {
            Some(CANCEL_ABORTED)
        };
        self.stats[stat::LAST_DISPOSITION].store(u64::from(d.unwrap_or(0)), Ordering::SeqCst);
        d
    }

    /// One `on_piece`, as the test plane answers it: the outcome, and whether it is held.
    unsafe fn piece(&self, t: Ticket, i: &OnPieceIn, o: &mut OnPieceOut) -> (Answered, Hold) {
        self.count(stat::ON_PIECES);
        self.stats[stat::UNIT].store(i.unit, Ordering::SeqCst);
        self.caller_refs
            .lock()
            .unwrap()
            .push(text(i.caller_ref).to_vec());
        if i.stream != 0 {
            return (self.session_piece(i, o), Hold::No);
        }
        let Some(head) = self.heads.lock().unwrap().get(&i.unit).cloned() else {
            // A piece of a unit that never arrived: the caller's head is not re-sent.
            return (ready(Outcome::Fault), Hold::No);
        };
        self.tickets.lock().unwrap().insert(t, i.unit);
        if i.from == FROM_KERNEL && i.flags & PIECE_REFUSED != 0 {
            // THE REFUSED PIECE: the plane writes the record `refused` = the reason's code, and
            // answers bytes, a status and done, none of which may reach the caller.
            self.refused.lock().unwrap().push(i.reason);
            let mut at = 0;
            let key = put(i, &mut at, b"refused");
            let value = put(i, &mut at, i.reason.to_string().as_bytes());
            *i.records_buf = RecordWrite {
                kind: 0,
                op: RECORD_PUT,
                key,
                value,
            };
            o.records_written = 1;
            o.arena_written = at as u64;
            let n = NOT_FOR_THE_CALLER.len().min(i.reply_cap);
            std::ptr::copy_nonoverlapping(NOT_FOR_THE_CALLER.as_ptr(), i.reply_buf, n);
            o.emitted = n as u64;
            o.reply_status = 299;
            o.flags = EMIT_DONE;
            return (ready(Outcome::Ready), Hold::No);
        }
        let mut units = self.units.lock().unwrap();
        let u = units.entry(i.unit).or_default();
        let piece = bytes(i.bytes);
        if let Some(from) = u.more_from.take() {
            // The re-call after `more = 1`: the same source, no bytes, no flags.
            if i.from != from || !piece.is_empty() || i.flags != 0 {
                return (ready(Outcome::Fault), Hold::No);
            }
        }
        match i.from {
            FROM_KERNEL if i.attempt_no > 0 => {
                *u = Unit {
                    mode: text(i.member).to_vec(),
                    attempt: i.attempt_no,
                    ..Unit::default()
                };
                return (ready(Outcome::Ready), Hold::No);
            }
            FROM_CALLER => {
                if head.starts_with(b"/scope-local") {
                    self.scope_members
                        .lock()
                        .unwrap()
                        .push((i.attempt_no, text(i.member).to_vec()));
                }
                u.body.extend_from_slice(piece);
                if i.flags & PIECE_LAST == 0 {
                    return (ready(Outcome::Ready), Hold::No);
                }
                if head.as_slice() == b"/local" || head.as_slice() == b"/scope-local" {
                    // A LOCAL ANSWER: the plane answers the caller itself (an echo of the body),
                    // with nothing for the far end.
                    o.reply_status = 200;
                    let n = u.body.len().min(i.reply_cap);
                    std::ptr::copy_nonoverlapping(u.body.as_ptr(), i.reply_buf, n);
                    o.emitted = n as u64;
                    o.flags = EMIT_DONE;
                    return (ready(Outcome::Ready), Hold::No);
                }
                if head.as_slice() == b"/audit" {
                    // A plane that audits its unit and names its ledger lane (SEAM-L(j), (k)): one
                    // reported unit, the lane `tool_x`, one audit row `thing.call` on `thing:x`
                    // applied, answered locally with nothing.
                    let mut at = 0;
                    let key = put(i, &mut at, b"thing.call");
                    let value = put(i, &mut at, b"thing:x");
                    *i.records_buf = RecordWrite {
                        kind: AUDIT_APPLIED,
                        op: RECORD_AUDIT,
                        key,
                        value,
                    };
                    o.records_written = 1;
                    o.lane = put(i, &mut at, b"tool_x");
                    *i.units_buf = UnitCount {
                        class: 0,
                        source: UNITS_REPORTED,
                        amount: 1,
                    };
                    o.units_written = 1;
                    o.arena_written = at as u64;
                    o.reply_status = 200;
                    o.flags = EMIT_DONE;
                    return (ready(Outcome::Ready), Hold::No);
                }
                if head.as_slice() == b"/records" {
                    // A plane that writes records: `key=value;...` puts, an empty value a
                    // tombstone; it answers locally with nothing. The body is taken: the cases
                    // drive every unit under one key.
                    let (mut at, mut n) = (0, 0);
                    for kv in std::mem::take(&mut u.body).split(|b| *b == b';') {
                        let eq = kv.iter().position(|b| *b == b'=').unwrap_or(kv.len());
                        let key = put(i, &mut at, &kv[..eq]);
                        let value = put(i, &mut at, kv.get(eq + 1..).unwrap_or_default());
                        *i.records_buf.add(n) = RecordWrite {
                            kind: 0,
                            op: RECORD_PUT,
                            key,
                            value,
                        };
                        n += 1;
                    }
                    o.records_written = n as u32;
                    o.arena_written = at as u64;
                    o.reply_status = 204;
                    o.flags = EMIT_DONE;
                    return (ready(Outcome::Ready), Hold::No);
                }
                let mut at = 0;
                o.verb = put(i, &mut at, b"POST");
                o.target = put(i, &mut at, &[b"/far/".as_slice(), &u.mode, &head].concat());
                let name = put(i, &mut at, b"x-attempt");
                let value = put(i, &mut at, u.attempt.to_string().as_bytes());
                *i.fields_buf = OutField { name, value };
                o.fields_written = 1;
                o.arena_written = at as u64;
                let n = u.body.len().min(i.reply_cap);
                std::ptr::copy_nonoverlapping(u.body.as_ptr(), i.reply_buf, n);
                o.emitted = n as u64;
                o.flags = EMIT_TO_FAR_END;
                return (ready(Outcome::Ready), Hold::No);
            }
            _ => {}
        }
        let mut hold = Hold::No;
        if i.from == FROM_FAR_END && (!piece.is_empty() || i.flags != 0) {
            u.far_answered = true;
            u.far_pieces += 1;
            // The answer's head (its status, not a trailer's) carries the final mark; a new attempt
            // starts with none (the ATTEMPT piece resets the unit above).
            if i.flags & PIECE_HAS_STATUS != 0 && i.flags & PIECE_FIELDS == 0 {
                u.final_answer = i.flags & PIECE_FINAL != 0;
            }
            u.saw_last |= i.flags & PIECE_LAST != 0;
            match u.mode.as_slice() {
                b"fault" => return (ready(Outcome::Fault), Hold::No),
                // The watchdog's FAULT for a crossing that has not returned: see `Hold::Wedge`.
                b"wedge" => return (ready(Outcome::Fault), Hold::Wedge),
                b"hang" | b"hang-row" | b"cancel-fault" => {
                    return (ready(Outcome::Pending), Hold::Forever)
                }
                b"pend" if !u.pended => {
                    u.pended = true;
                    self.count(stat::HOST_CALLS);
                    hold = Hold::For(Duration::from_millis(30));
                }
                // An answer whose last window (its reply done) comes LATE (mode `done-late`): the
                // second far-end piece's answer is held, so a deadline, a drain or the caller
                // going away reaches the op before its own done answer does.
                b"done-late" | b"retry-done-late" if u.far_pieces == 2 => {
                    hold = Hold::For(DONE_LATE);
                }
                b"retry" => {
                    o.verdict = VERDICT_RETRY;
                    return (ready(Outcome::Ready), Hold::No);
                }
                // An answer done before any byte, with a retry verdict (mode `done-retry`): the
                // kernel fails it over, and the plane keeps the unit for the next attempt.
                b"done-retry" => {
                    o.flags = EMIT_DONE;
                    o.verdict = VERDICT_RETRY;
                    return (ready(Outcome::Ready), Hold::No);
                }
                b"short" | b"short-twice" if u.short => {
                    // The dispatcher's rule: a second short answer on the re-call is FAULT.
                    if u.mode == b"short-twice" {
                        return (ready(Outcome::Fault), Hold::No);
                    }
                    u.short = false;
                }
                b"short" | b"short-twice" if i.units_cap < 12 => {
                    u.short = true;
                    o.units_needed = 12;
                    let a = Answered {
                        outcome: Outcome::Failed,
                        short: true,
                        disposition: None,
                    };
                    u.far_pieces -= 1;
                    return (a, Hold::No);
                }
                _ => {}
            }
            if i.flags & PIECE_FIELDS == 0 {
                u.pending.extend_from_slice(piece);
            } else if u.mode == b"trailers" {
                // A plane that reads the far end's trailers.
                u.pending.push(b'[');
                u.pending.extend_from_slice(piece);
                u.pending.push(b']');
            }
            if u.mode == b"retry-late" && u.far_pieces == 2 {
                o.verdict = VERDICT_RETRY;
            }
        }
        if u.far_pieces == 1 && !u.streamed {
            o.reply_status = if i.flags & PIECE_HAS_STATUS != 0 {
                i.status_code
            } else {
                200
            };
            let mut at = 0;
            let name = put(i, &mut at, b"content-type");
            let value = put(i, &mut at, b"text/plain");
            *i.fields_buf = OutField { name, value };
            o.fields_written = 1;
            o.arena_written = at as u64;
            // A plane whose usage tap could not read the answer (modes `tap-bad-json`,
            // `tap-unknown`, the latter a byte outside the vocabulary): the fault rides the answer
            // that opens the reply, once.
            o.tap_fault = match u.mode.as_slice() {
                b"tap-bad-json" => busbar_contract::abi::plane::TAP_FAULT_BAD_JSON,
                b"tap-unknown" => 0xC8,
                _ => busbar_contract::abi::plane::TAP_FAULT_NONE,
            };
        }
        // A plane that writes a record on its answer's second window (mode `row-late`): with no
        // record path for it (the store out), the write fails the unit after its answer began.
        if u.mode == b"row-late" && u.far_pieces == 2 {
            let mut at = o.arena_written as usize;
            let key = put(i, &mut at, b"late");
            let value = put(i, &mut at, b"row");
            *i.records_buf = RecordWrite {
                kind: 0,
                op: RECORD_PUT,
                key,
                value,
            };
            o.records_written = 1;
            o.arena_written = at as u64;
        }
        let n = u.pending.len().min(i.reply_cap);
        std::ptr::copy_nonoverlapping(u.pending.as_ptr(), i.reply_buf, n);
        u.pending.drain(..n);
        u.emitted += n as u64;
        u.streamed |= n > 0;
        o.emitted = n as u64;
        o.more = u32::from(!u.pending.is_empty() && n > 0);
        u.more_from = (o.more == 1).then_some(i.from);
        let wide = if u.mode.starts_with(b"short") { 12 } else { 1 };
        for k in 0..wide {
            *i.units_buf.add(k) = UnitCount {
                class: 0,
                source: UNITS_REPORTED,
                amount: u.emitted,
            };
        }
        o.units_written = wide as u32;
        if u.saw_last && u.pending.is_empty() {
            o.flags = EMIT_DONE;
            o.verdict = 0;
            // A done answer with a retry verdict (mode `retry-done-late`): an answer not marked
            // final keeps the unit for the attempt the retry asks for.
            if u.mode == b"retry-done-late" {
                o.verdict = VERDICT_RETRY;
            }
        }
        // A plane whose emitted messages are text (mode `text`): each whole message says so.
        if u.mode == b"text" && o.emitted > 0 && o.more == 0 {
            o.flags |= PIECE_OUT_TEXT;
        }
        // A plane that frames messages (mode `framed`): each far-end piece is ONE message, its end
        // on the answer that empties it; its reply closes with a final status (5, its words and
        // two details bytes) in the arena.
        if u.mode == b"framed" {
            if o.emitted > 0 && o.more == 0 {
                o.flags |= EMIT_MESSAGE_END;
            }
            if o.flags & EMIT_DONE != 0 {
                let mut at = o.arena_written as usize;
                o.final_message = put(i, &mut at, b"not here");
                o.final_details = put(i, &mut at, &[1, 2]);
                o.final_status = 5;
                o.arena_written = at as u64;
                o.flags |= EMIT_FINAL_STATUS;
            }
        }
        (ready(Outcome::Ready), hold)
    }
}

impl Double {
    /// A session's piece: the caller's piece opens it (`200`, `open:<body>`), a collection answers
    /// the output a tick owed (`keepalive;`), and the caller's last piece ends it.
    unsafe fn session_piece(&self, i: &OnPieceIn, o: &mut OnPieceOut) -> Answered {
        let s = &self.sessions;
        let reply = |o: &mut OnPieceOut, bytes: &[u8]| {
            let n = bytes.len().min(i.reply_cap);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.reply_buf, n);
            o.emitted = n as u64;
        };
        match i.from {
            FROM_CALLER if i.flags & PIECE_LAST != 0 => {
                s.open.lock().unwrap().retain(|k| *k != i.stream);
                o.flags = EMIT_DONE;
            }
            FROM_CALLER => {
                let body = bytes(i.bytes).to_vec();
                s.read.lock().unwrap().push((i.stream, body.clone()));
                s.open.lock().unwrap().push(i.stream);
                o.reply_status = 200;
                reply(o, &[b"open:".as_slice(), &body].concat());
            }
            FROM_KERNEL if i.attempt_no == 0 => {
                s.collects.fetch_add(1, Ordering::SeqCst);
                reply(o, b"keepalive;");
            }
            _ => return ready(Outcome::Refused),
        }
        ready(Outcome::Ready)
    }
}

enum Hold {
    No,
    For(Duration),
    Forever,
    /// Answered FAULT (as the watchdog answers a hung crossing) while the crossing goes on: it
    /// returns later, re-reading its input and writing its reply buffer, and only then lets go of
    /// what the driver lent it.
    Wedge,
}

/// How long a `done-late` unit's last answer is held.
pub(crate) const DONE_LATE: Duration = Duration::from_millis(120);

/// How long a wedged crossing runs on after its FAULT answer.
pub(crate) const WEDGE: Duration = Duration::from_millis(300);

struct SendIn(OnPieceIn);
// SAFETY: the driver's `in`; its buffers are owned by the lent memory the wedge holds with it.
unsafe impl Send for SendIn {}

impl PlaneCalls for Double {
    fn now_ns(&self) -> u64 {
        now_ns()
    }

    fn arrive(
        &self,
        input: &mut ArriveIn,
        out: &mut ArriveOut,
        grow: Grow<'_, ArriveIn, ArriveOut>,
    ) -> Outcome {
        let target = unsafe { text(input.target) }.to_vec();
        self.heads
            .lock()
            .unwrap()
            .insert(input.unit, target.clone());
        let estimate = |amount| UnitCount {
            class: 0,
            source: UNITS_ESTIMATED,
            amount,
        };
        // `/trusted/<counterparty>[/<capability>[@<digest>]]`: the unit states its trust facts,
        // which the kernel's Approve judges (the plane judges none).
        if let Some(rest) = target.strip_prefix(b"/trusted/") {
            let leak = |b: &[u8]| -> AbiStr {
                let kept: &'static [u8] = Box::leak(b.to_vec().into_boxed_slice());
                AbiStr::over(kept)
            };
            let (cp, cap) = match rest.iter().position(|b| *b == b'/') {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            };
            out.trust_counterparty = leak(cp);
            if let Some(cap) = cap {
                let (cap, digest) = match cap.iter().position(|b| *b == b'@') {
                    Some(i) => (&cap[..i], Some(&cap[i + 1..])),
                    None => (cap, None),
                };
                out.trust_item = leak(cap);
                if let Some(d) = digest {
                    out.trust_digest = leak(d);
                }
            }
        }
        for call in 0..2 {
            let cap = input.units_cap;
            let wants: Vec<UnitCount> = match target.as_slice() {
                // A path that takes POST only: another method is the plane's own 405.
                b"/post-only" if unsafe { text(input.method) } != b"POST" => {
                    out.refusal = 9;
                    out.refusal_status = 405;
                    return Outcome::Refused;
                }
                b"/refuse" => {
                    // The plane's own decode refusal: its code, and the 4xx it wears.
                    out.refusal = 7;
                    out.refusal_status = 404;
                    return Outcome::Refused;
                }
                b"/refuse-words" => {
                    // The same refusal, stating why in its own words (`head.error`).
                    out.refusal = 7;
                    out.refusal_status = 400;
                    out.head.error = AbiStr::over(REFUSAL_WORDS);
                    return Outcome::Refused;
                }
                b"/refuse-entry" | b"/refuse-entry-after" => {
                    // A REFUSAL ABOUT AN ENTRY (rule 6): it names the pool it concerns, with its
                    // operation class and dialect, and wears the plane's own code and status;
                    // `-after` states it rendered after that entry's admission.
                    out.refusal = ENTRY_REFUSED;
                    out.refusal_status = ENTRY_REFUSED_STATUS;
                    out.route = ROUTE_POOL;
                    out.pool = AbiStr::over(b"entry-pool");
                    out.op_class = 0;
                    out.dialect = 0;
                    if target.as_slice() == b"/refuse-entry-after" {
                        out.refusal_flags = REFUSED_AFTER_ADMISSION;
                    }
                    return Outcome::Refused;
                }
                b"/scope-local" | b"/scope-local-far" => {
                    // A unit the plane answers itself at its scope's one entry (ROUTE_SCOPE_LOCAL).
                    out.route = ROUTE_SCOPE_LOCAL;
                    vec![estimate(0)]
                }
                b"/session" => {
                    // A unit served as a duplex session, answered by the plane itself.
                    out.route = ROUTE_LOCAL;
                    out.route_flags = ROUTE_SESSION;
                    vec![estimate(0)]
                }
                b"/short-twice" => vec![estimate(0); cap + 1],
                b"/short" => vec![estimate(1), estimate(2)],
                _ => vec![estimate(input.body.len as u64)],
            };
            if wants.len() > cap {
                if call == 1 {
                    return Outcome::Fault;
                }
                out.units_needed = wants.len() as u32;
                grow(out, input);
                continue;
            }
            for (k, u) in wants.iter().enumerate() {
                // SAFETY: the driver's buffer of `units_cap` counts.
                unsafe { *input.units_buf.add(k) = *u };
            }
            out.units_written = wants.len() as u32;
            out.op_class = 0;
            out.dialect = 0;
            out.principal_need = PRINCIPAL_OPTIONAL;
            return Outcome::Ready;
        }
        Outcome::Fault
    }

    fn arrived_pool(&self, out: &ArriveOut) -> Option<Vec<u8>> {
        (!out.pool.ptr.is_null()).then(|| unsafe { text(out.pool) }.to_vec())
    }

    fn arrived_refusal(&self, out: &ArriveOut) -> Option<Vec<u8>> {
        (!out.head.error.ptr.is_null()).then(|| unsafe { text(out.head.error) }.to_vec())
    }

    fn arrived_trust(&self, out: &ArriveOut) -> Option<ArrivedTrust> {
        let read = |s: AbiStr| (!s.ptr.is_null()).then(|| unsafe { text(s) }.to_vec());
        Some(ArrivedTrust {
            counterparty: read(out.trust_counterparty)?,
            item: read(out.trust_item),
            digest: read(out.trust_digest),
        })
    }

    fn refusal(
        &self,
        input: &mut RefusalIn,
        out: &mut RefusalOut,
        grow: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        if input.unit != 0 {
            self.closed(input.unit);
        }
        // The reason crosses beside its text (`RefusalIn::text`, the kernel's own message: the
        // reason's spelling, or the walk terminal's own words): a refusal whose code names no reason,
        // or that carries no text, is FAULT. A gate's refusal carries the hook's own words instead.
        let named = busbar_contract::abi::plane::reason_of(input.reason);
        if input.cause != REFUSAL_GATE
            && (named.is_none() || unsafe { text(input.text) }.is_empty())
        {
            return Outcome::Fault;
        }
        let mut body = [
            if input.cause == REFUSAL_ARRIVE {
                b"words:".as_slice()
            } else {
                b"".as_slice()
            },
            b"refused:".as_slice(),
            input.status.to_string().as_bytes(),
            b":",
            unsafe { text(input.text) },
        ]
        .concat();
        // The target crosses beside every refusal (one may precede `arrive`): this plane names it
        // when the target asks.
        let target = unsafe { text(input.target) };
        if target == b"/target-echo" {
            body.extend_from_slice(b" for ");
            body.extend_from_slice(target);
        }
        // A Retry-After the kernel hands (the walk's exhaustion terminal): this plane names it.
        if input.retry_after_s != 0 {
            body.extend_from_slice(format!(":retry={}", input.retry_after_s).as_bytes());
        }
        if input.plane_code != 0 {
            body.extend_from_slice(format!(":{}@{}", input.plane_code, input.unit).as_bytes());
        }
        // Why the kernel's Approve did not trust the unit: this plane names the `TRUST_*` code.
        if input.trust != 0 {
            body.extend_from_slice(format!(":trust={}", input.trust).as_bytes());
        }
        // A HOOK VETO (SEAM-L(o), (p)): this plane names the vetoing hook and writes its audit row,
        // rejected, for the unit the kernel refused.
        let hook = unsafe { text(input.hook) }.to_vec();
        if !hook.is_empty() {
            body.extend_from_slice(b":hook=");
            body.extend_from_slice(&hook);
        }
        let (row_key, row_value) = (b"thing.call".as_slice(), b"thing:x".as_slice());
        let rows = usize::from(!hook.is_empty());
        let (name, value) = (b"content-type".as_slice(), b"text/plain".as_slice());
        let arena = name.len() + value.len() + rows * (row_key.len() + row_value.len());
        for call in 0..2 {
            if body.len() > input.reply_cap
                || input.fields_cap < 1
                || arena > input.arena_cap
                || rows > input.records_cap
            {
                if call == 1 {
                    return Outcome::Fault;
                }
                out.reply_needed = body.len() as u64;
                out.fields_needed = 1;
                out.arena_needed = arena as u64;
                out.records_needed = rows as u32;
                grow(out, input);
                continue;
            }
            if rows == 1 {
                let at = name.len() + value.len();
                // SAFETY: the driver's arena and records buffer, of the capacities checked above.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        row_key.as_ptr(),
                        input.arena_buf.add(at),
                        row_key.len(),
                    );
                    std::ptr::copy_nonoverlapping(
                        row_value.as_ptr(),
                        input.arena_buf.add(at + row_key.len()),
                        row_value.len(),
                    );
                    *input.records_buf = RecordWrite {
                        kind: busbar_contract::abi::plane::AUDIT_REJECTED,
                        op: RECORD_AUDIT,
                        key: Span {
                            offset: at as u32,
                            len: row_key.len() as u32,
                        },
                        value: Span {
                            offset: (at + row_key.len()) as u32,
                            len: row_value.len() as u32,
                        },
                    };
                }
                out.records_written = 1;
            }
            // SAFETY: the driver's buffers, of the capacities checked above.
            unsafe {
                std::ptr::copy_nonoverlapping(body.as_ptr(), input.reply_buf, body.len());
                std::ptr::copy_nonoverlapping(name.as_ptr(), input.arena_buf, name.len());
                std::ptr::copy_nonoverlapping(
                    value.as_ptr(),
                    input.arena_buf.add(name.len()),
                    value.len(),
                );
                *input.fields_buf = OutField {
                    name: Span {
                        offset: 0,
                        len: name.len() as u32,
                    },
                    value: Span {
                        offset: name.len() as u32,
                        len: value.len() as u32,
                    },
                };
            }
            out.reply_written = body.len() as u64;
            out.fields_written = 1;
            out.arena_written = arena as u64;
            return Outcome::Ready;
        }
        Outcome::Fault
    }

    /// The view this plane projects: each body line `role:text` is a turn, a `sys=` line the
    /// system prompt and a `user=` line the end user. A rewrite (1.5.5's `rewrite` object) is
    /// applied by replacing the turns with its messages' `role:content`, unless the target is
    /// `/no-rewrite` (a rewrite the plane cannot read); `/unprojectable` refuses to project, and
    /// `/refuses-rewrite` refuses to project with a rewrite (one naming a model other than the
    /// routed one, say) while it projects the caller's own request; `/faults-rewrite` answers FAULT
    /// to a project with a rewrite (a redaction the plane cannot apply), and `/unparseable` to every
    /// project (a body whose document does not parse), marked `PROJECT_FAULT_UNPARSEABLE`;
    /// `/fault-unmarked` answers FAULT without the mark, `/panics` as a panicking slot's door does,
    /// `/no-crossing` as the host does for a refused frame or a quarantined instance, and
    /// `/broken-answer` is a FAULT the host minted over a READY answer that broke the kind's rule.
    /// The
    /// view names the entry its `arrive` recorded (none) and states the unit's body: a projection
    /// with no body would leave a gate-first unit nothing to screen, and the kernel would bind no
    /// gate for it.
    fn project(
        &self,
        input: &mut ProjectIn,
        out: &mut ProjectOut,
        grow: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome {
        let target = unsafe { text(input.target) }.to_vec();
        let body = unsafe { bytes(input.body) }.to_vec();
        let rewrite = unsafe { bytes(input.rewrite) }.to_vec();
        self.projects
            .lock()
            .unwrap()
            .push((body.clone(), rewrite.clone()));
        if (target == b"/faults-rewrite" && !rewrite.is_empty()) || target == b"/unparseable" {
            // The plane's own FAULT over a body it could not parse: its door mirrors the outcome
            // into the `out` head, and the plane marks the body unparseable.
            out.head.outcome = RawOutcome::of(Outcome::Fault);
            out.view.flags = busbar_contract::abi::plane::PROJECT_FAULT_UNPARSEABLE;
            return Outcome::Fault;
        }
        match target.as_slice() {
            // A FAULT the plane answered without the mark.
            b"/fault-unmarked" => {
                out.head.outcome = RawOutcome::of(Outcome::Fault);
                return Outcome::Fault;
            }
            // A slot that panicked: the door's catcher writes nothing but `outcome = FAULT`.
            b"/panics" => {
                out.head.outcome = RawOutcome::of(Outcome::Fault);
                return Outcome::Fault;
            }
            // A frame refused before the crossing, or a quarantined instance: the host answers
            // FAULT and the `out` is as the host lent it.
            b"/no-crossing" => return Outcome::Fault,
            // The plane answered READY (the mark's bit set among its view flags, even) and the
            // loader's check of that answer against its kind's rule refused it: a FAULT the host
            // minted.
            b"/broken-answer" => {
                out.head.outcome = RawOutcome::of(Outcome::Ready);
                out.view.flags = busbar_contract::abi::plane::PROJECT_FAULT_UNPARSEABLE;
                return Outcome::Fault;
            }
            _ => {}
        }
        if target == b"/unprojectable" || (target == b"/refuses-rewrite" && !rewrite.is_empty()) {
            return Outcome::Refused;
        }
        let rewritten = (!rewrite.is_empty() && target != b"/no-rewrite")
            .then(|| serde_json::from_slice::<serde_json::Value>(&rewrite).ok())
            .flatten()
            .and_then(|v| v.get("messages").and_then(|m| m.as_array()).cloned())
            .map(|messages| {
                let lines: Vec<String> = messages
                    .iter()
                    .map(|m| {
                        let field = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("");
                        format!("{}:{}", field("role"), field("content"))
                    })
                    .collect();
                lines.join("\n").into_bytes()
            });
        let unit_body = body.clone();
        let effective = rewritten.clone().unwrap_or(body);
        let effective = String::from_utf8_lossy(&effective).into_owned();
        let (mut system, mut user, mut turns) = (None, None, Vec::new());
        for line in effective.split('\n').filter(|l| !l.is_empty()) {
            if let Some(v) = line.strip_prefix("sys=") {
                system = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("user=") {
                user = Some(v.to_string());
            } else {
                let (role, text) = line.split_once(':').unwrap_or(("user", line));
                turns.push((role.to_string(), text.to_string()));
            }
        }
        let mut strings: Vec<&[u8]> = vec![b"", b"test-dialect"];
        strings.push(system.as_deref().unwrap_or("").as_bytes());
        strings.push(user.as_deref().unwrap_or("").as_bytes());
        for (role, text) in &turns {
            strings.push(role.as_bytes());
            strings.push(text.as_bytes());
        }
        let rewritten_bytes = rewritten.unwrap_or_default();
        strings.push(&unit_body);
        strings.push(&rewritten_bytes);
        let arena: usize = strings.iter().map(|b| b.len()).sum();
        for call in 0..2 {
            if turns.len() > input.messages_cap || arena > input.arena_cap {
                if call == 1 {
                    return Outcome::Fault;
                }
                out.messages_needed = turns.len() as u32;
                out.arena_needed = arena as u64;
                grow(out, input);
                *out = busbar_contract::abi::sdk::door::blank_out();
                continue;
            }
            // SAFETY (below): the driver's buffers, of the capacities checked above.
            let mut at = 0usize;
            let mut place = |b: &[u8]| -> AbiStr {
                unsafe {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), input.arena_buf.add(at), b.len())
                };
                let s = AbiStr {
                    ptr: unsafe { input.arena_buf.add(at) }.cast_const(),
                    len: b.len(),
                };
                at += b.len();
                s
            };
            let pool = place(strings[0]);
            let dialect = place(strings[1]);
            let sys = place(strings[2]);
            let end_user = place(strings[3]);
            for (k, pair) in strings[4..4 + 2 * turns.len()].chunks(2).enumerate() {
                let role = place(pair[0]);
                let text = place(pair[1]);
                unsafe { *input.messages_buf.add(k) = MessageView { role, text } };
            }
            let _ = place(&unit_body);
            let _ = place(&rewritten_bytes);
            let start = arena - rewritten_bytes.len();
            let body_start = start - unit_body.len();
            out.view = RequestView {
                request_id: 0,
                pool,
                ingress_dialect: dialect,
                message_count: turns.len() as u64,
                total_chars: turns.iter().map(|(_, t)| t.len() as u64).sum(),
                max_tokens: 0,
                flags: 0,
                signals: input.signals_buf.cast_const(),
                signals_len: 0,
                session: Blob {
                    ptr: std::ptr::null(),
                    len: 0,
                    fmt: busbar_contract::abi::mechanism::call::BLOB_ABSENT,
                    flags: 0,
                },
            };
            out.prompt.system = sys;
            out.prompt.message_count = turns.len() as u64;
            out.prompt.messages = input.messages_buf.cast_const();
            out.prompt.messages_len = turns.len();
            out.end_user = end_user;
            out.body = if unit_body.is_empty() {
                Span {
                    offset: busbar_contract::abi::plane::SPAN_ABSENT,
                    len: 0,
                }
            } else {
                Span {
                    offset: body_start as u32,
                    len: unit_body.len() as u32,
                }
            };
            out.rewritten = Span {
                offset: start as u32,
                len: rewritten_bytes.len() as u32,
            };
            out.arena_written = arena as u64;
            return Outcome::Ready;
        }
        Outcome::Fault
    }

    fn cancel(&self, ticket: Ticket, unit: u64) -> Option<busbar_contract::plane_calls::Cancelled> {
        self.count(stat::CANCELS);
        // THE PLANE'S UNIT TABLE, keyed from `arrive`: a cancel frees the unit it names, or the one
        // a piece already taught it the ticket of.
        let named = (unit != 0).then_some(unit);
        let taught = self.tickets.lock().unwrap().get(&ticket).copied();
        if let Some(key) = named.or(taught) {
            self.heads.lock().unwrap().remove(&key);
            self.closed(key);
        }
        let u = self.unit_of(ticket);
        self.disposition(&u)
            .map(|disposition| busbar_contract::plane_calls::Cancelled {
                disposition,
                writes: self.cancel_row(&u),
            })
    }

    fn mint(&self) -> Option<Ticket> {
        Some(Ticket {
            slot: self.next.fetch_add(1, Ordering::SeqCst),
            generation: 1,
        })
    }

    fn recycle(&self, ticket: Ticket) {
        self.recycled.lock().unwrap().push(ticket);
    }

    fn declared(&self) -> InstanceDecl {
        self.declared.clone()
    }

    fn driver(&self) -> Option<Ticket> {
        let t = self.mint()?;
        self.drivers.lock().unwrap().push(t);
        Some(t)
    }

    fn tick(&self, driver: Ticket, now: u64) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        assert!(
            self.drivers.lock().unwrap().contains(&driver),
            "tick on the driver ticket"
        );
        self.ticks.lock().unwrap().push(now);
        // Every open session owes output on the tick: `drive` names it.
        let open = self.sessions.open.lock().unwrap().clone();
        if !open.is_empty() {
            self.sessions.named.lock().unwrap().extend(open);
            self.sessions.told.notify_one();
        }
        let every = self.tick_every_ns.load(Ordering::SeqCst);
        let next = if every == 0 { 0 } else { now + every };
        Box::pin(std::future::ready(Some(next)))
    }

    fn woke(&self) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let line = Arc::clone(&self.wake);
        Box::pin(async move {
            if !line.channel.load(Ordering::SeqCst) {
                return false;
            }
            line.told.notified().await;
            true
        })
    }

    /// The streams its ticks named, waiting until one is.
    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>> {
        let sessions = Arc::clone(&self.sessions);
        Box::pin(async move {
            loop {
                let told = sessions.told.notified();
                let named = std::mem::take(&mut *sessions.named.lock().unwrap());
                if !named.is_empty() {
                    return named;
                }
                told.await;
            }
        })
    }

    /// The client-drop path: an op held on `ticket` is cancelled "on its worker" and answers the
    /// plane kind's timeout outcome with the disposition (or FAULT when the cancel FAULTs).
    fn drop_client(&self, ticket: Ticket) {
        let Some((slot, out)) = self.held.lock().unwrap().remove(&ticket) else {
            return;
        };
        self.count(stat::CANCELS);
        self.count(stat::CANCELS_ON_WORKER);
        if let Some(key) = self.tickets.lock().unwrap().get(&ticket).copied() {
            self.closed(key);
        }
        let u = self.unit_of(ticket);
        let answer = match self.disposition(&u) {
            Some(d) => Answered {
                outcome: Outcome::Failed,
                short: false,
                disposition: Some(d),
            },
            None => ready(Outcome::Fault),
        };
        if answer.disposition.is_some() {
            slot.0.lock().unwrap().writes = self.cancel_row(&u);
        }
        slot.put(answer, out);
    }

    fn on_piece(
        &self,
        ticket: Ticket,
        input: OnPieceIn,
        mut out: OnPieceOut,
        lent: Lent,
    ) -> Box<dyn PieceInFlight> {
        let slot = Arc::new(Shared(Mutex::new(Slot {
            answer: None,
            waker: None,
            writes: Vec::new(),
        })));
        // SAFETY: the driver's `in`, whose buffers outlive the answer.
        let (answer, hold) = unsafe { self.piece(ticket, &input, &mut out) };
        // A done answer with a retry verdict keeps the unit for the kernel's next attempt, unless
        // its answer was marked final (`PIECE_FINAL`).
        let final_answer = (self.units.lock().unwrap())
            .get(&input.unit)
            .is_some_and(|u| u.final_answer);
        if answer.outcome == Outcome::Ready
            && out.flags & EMIT_DONE != 0
            && out.more == 0
            && (out.verdict != VERDICT_RETRY || final_answer)
            && input.flags & PIECE_REFUSED == 0
        {
            self.closed(input.unit);
        }
        match hold {
            Hold::No => slot.put(answer, out),
            Hold::Forever => {
                self.held
                    .lock()
                    .unwrap()
                    .insert(ticket, (slot.clone(), out));
            }
            Hold::Wedge => {
                slot.put(answer, out);
                let input = SendIn(input);
                std::thread::spawn(move || {
                    let input = input;
                    std::thread::sleep(WEDGE);
                    let i = input.0;
                    // SAFETY: the crossing still owns the buffers: `lent` is held until here.
                    if i.bytes.len != 0 {
                        unsafe {
                            let seen = std::slice::from_raw_parts(i.bytes.ptr, i.bytes.len);
                            let n = seen.len().min(i.reply_cap);
                            std::ptr::copy(seen.as_ptr(), i.reply_buf, n);
                        }
                    }
                    // The crossing returns: only now may what it was lent go.
                    drop(lent);
                });
            }
            Hold::For(after) => {
                let (slot, answer, out) = (slot.clone(), answer, SendOut(out));
                std::thread::spawn(move || {
                    std::thread::sleep(after);
                    let out = out;
                    slot.put(answer, out.0);
                });
            }
        }
        Box::new(Flight(slot))
    }

    fn serve(&self, _: Ticket, _: ServeIn, _: ServeOut, _: Lent) -> Box<dyn ServeInFlight> {
        Box::new(NoServe)
    }
}

/// The double serves no admin route: every `serve` answers FAULT at once.
struct NoServe;

impl Future for NoServe {
    type Output = Answered;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        Poll::Ready(Answered {
            outcome: Outcome::Fault,
            short: false,
            disposition: None,
        })
    }
}

impl ServeInFlight for NoServe {
    fn out(&self) -> Option<ServeOut> {
        None
    }
}

struct SendOut(OnPieceOut);
// SAFETY: plain data the double wrote; its pointers are never dereferenced.
unsafe impl Send for SendOut {}

/// The flush epoch is one counter however many handles hold it: the flush tick bumps it, and every
/// money seam reading a clone sees the same epoch.
#[test]
fn the_flush_epoch_is_one_counter_across_its_clones() {
    let epoch = busbar_kernel::plane_driver::FlushEpoch::new();
    let reader = epoch.clone();
    assert_eq!(reader.now(), 0);
    epoch.bump();
    epoch.bump();
    assert_eq!(reader.now(), 2, "a clone reads the bumps of the tick");
}

// ── record writes ────────────────────────────────────────────────────────────────────────────────

use busbar_contract::abi::host::service as svc;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_contract::services::{Caller as Instance, HostServices, Ran, RecordsList, Stored};
use busbar_kernel::governance::MemoryStore;
use busbar_kernel::host_records::RecordRows;
use busbar_kernel::host_services::{InstanceFacts, KernelServices, Offload};

/// The memory store's typed records.
struct Rows(Arc<MemoryStore>);

impl RecordRows for Rows {
    fn record_put(&self, s: RecordSchemaId, k: &[u8], v: &RecordBytes) -> Result<(), StoreError> {
        self.0.record_put(s, k, v)
    }

    fn record_get(&self, s: RecordSchemaId, k: &[u8]) -> Result<Option<RecordBytes>, StoreError> {
        self.0.record_get(s, k)
    }

    fn record_scan(
        &self,
        s: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        self.0.record_scan(s, prefix, limit)
    }
}

/// Runs every store call at once, on the caller's thread.
struct Inline;

impl Offload for Inline {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

fn instance() -> Instance {
    Instance {
        instance: Arc::from("inst"),
        plugin: Arc::from("the-plane"),
        kind: KindCode::Plane,
    }
}

/// The kernel's records services over a memory store, the instance admitted with one kind.
fn records() -> Arc<KernelServices> {
    let store = Arc::new(MemoryStore::new());
    let s = KernelServices::new()
        .with_records(Arc::new(Rows(Arc::clone(&store))), store)
        .with_pool(Arc::new(Inline));
    let facts = InstanceFacts {
        record_kinds: vec![RecordSchemaId::new("task")],
        ..InstanceFacts::default()
    };
    s.admit("inst", facts).unwrap();
    Arc::new(s)
}

/// A may-pend service's answer.
fn answer(f: impl FnOnce(busbar_contract::services::Later) -> Ran) -> Stored {
    let slot = Arc::new(Mutex::new(None));
    let put = Arc::clone(&slot);
    match f(Box::new(move |s| *put.lock().unwrap() = Some(s))) {
        Ran::Now(s) => s,
        Ran::Later => slot.lock().unwrap().take().expect("answered"),
    }
}

fn get(s: &KernelServices, key: &[u8]) -> Stored {
    answer(|l| s.records_get(&instance(), "task", key, l))
}

fn list(s: &KernelServices) -> Vec<u8> {
    let all = RecordsList {
        kind: "task".into(),
        prefix: Vec::new(),
        after: None,
        limit: 0,
    };
    answer(|l| s.records_list(&instance(), all, l)).bytes
}

/// One unit whose plane writes `body`'s records and answers locally.
async fn write(driver: &PlaneDriver, body: &[u8]) -> busbar_contract::caps::Outcome {
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&[], &[]),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/records", body), 0);
    cases::drive(&units).await
}

/// THE PUMP APPLIES A PIECE'S RECORD WRITES (`RecordWrite`) through the kernel's record write
/// path, keyed by the instance: a put reads back through `records.get` and `records.list`, and a
/// put of an empty value is a tombstone that hides the record from both.
#[tokio::test]
async fn a_pieces_record_writes_reach_the_records_and_a_tombstone_hides_one() {
    let s = records();
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.driver = r.driver.with_records(Arc::clone(&s), instance());
    let done = |o| matches!(o, busbar_contract::caps::Outcome::Completed);
    assert!(done(write(&r.driver, b"a=1;b=2").await));
    let a = get(&s, b"a");
    assert_eq!((a.value, a.bytes.as_slice()), (svc::FOUND, &b"1"[..]));
    assert_eq!(list(&s), b"a1b2");
    assert!(done(write(&r.driver, b"a=").await));
    assert_eq!(get(&s, b"a").value, svc::ABSENT);
    assert_eq!(list(&s), b"b2");
}

/// A record write is never dropped: with no record path the unit that wrote it fails.
#[tokio::test]
async fn a_record_write_with_no_record_path_fails_the_unit() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let o = write(&r.driver, b"a=1").await;
    assert!(
        !matches!(o, busbar_contract::caps::Outcome::Completed),
        "{o:?}"
    );
}

/// The audit rows a driver wrote, as its sink saw them.
#[derive(Default)]
struct AuditRows(Mutex<Vec<(String, String, &'static str, String)>>);

impl busbar_kernel::plane_driver::AuditSink for AuditRows {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        self.0.lock().unwrap().push((
            action.to_string(),
            resource.to_string(),
            outcome,
            principal.to_string(),
        ));
    }
}

/// SEAM-L(k), THE DOOR UNIT'S AUDIT ROW: a plane's `RECORD_AUDIT` write on its answer is one row
/// on the kernel's audit chain, in the plane's words, under the principal the kernel verified,
/// with no record path (it is no record of the plane's); SEAM-L(j): the lane the same answer names
/// reaches the money steps. RED: the write failed the unit as an unknown record op, and the lane
/// was never read.
#[tokio::test]
async fn a_units_audit_row_reaches_the_kernels_chain_and_its_lane_the_money_steps() {
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let rows = Arc::new(AuditRows::default());
    r.driver = r.driver.with_audit(rows.clone());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&[], &[]),
        cases::Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/audit", b"x"), 0);
    let o = cases::drive(&units).await;
    assert!(
        matches!(o, busbar_contract::caps::Outcome::Completed),
        "{o:?}"
    );
    assert_eq!(
        *rows.0.lock().unwrap(),
        vec![(
            "thing.call".to_string(),
            "thing:x".to_string(),
            busbar_contract::vocab::OUTCOME_APPLIED,
            common::principal().as_str().to_string(),
        )],
        "one row, the plane's words, the kernel's principal"
    );
    assert_eq!(r.book.laned(), vec!["tool_x".to_string()]);
}

/// SEAM-L(t), A SERVED REQUEST'S RECORD WRITES: a put reaches the instance's records (read back
/// through `records.get`) and an audit row reaches the audit sink under the request's actor, in the
/// plane's order; a put with no record path, or an unknown op, answers 502. RED: the served answer
/// carried no record writes.
#[tokio::test]
async fn a_served_requests_record_writes_reach_the_records_and_the_audit_chain() {
    use busbar_kernel::plane_driver::serve::{write_served_records, Served, Unserved};
    let s = records();
    let rows = AuditRows::default();
    let served = Served {
        status: 200,
        fields: Vec::new(),
        body: Vec::new(),
        audit: 0,
        records: vec![
            (0, RECORD_PUT, b"cb".to_vec(), b"done".to_vec()),
            (
                AUDIT_APPLIED,
                RECORD_AUDIT,
                b"thing.callback".to_vec(),
                b"thing:x".to_vec(),
            ),
        ],
    };
    let path = (Arc::clone(&s), instance());
    write_served_records(Some(&path), &rows, &served, "acct:caller")
        .await
        .expect("written");
    let cb = get(&s, b"cb");
    assert_eq!((cb.value, cb.bytes.as_slice()), (svc::FOUND, &b"done"[..]));
    assert_eq!(
        *rows.0.lock().unwrap(),
        vec![(
            "thing.callback".to_string(),
            "thing:x".to_string(),
            busbar_contract::vocab::OUTCOME_APPLIED,
            "acct:caller".to_string(),
        )]
    );
    assert_eq!(
        write_served_records(None, &rows, &served, "acct:caller").await,
        Err(Unserved::Fault),
        "a put with no record path is never dropped"
    );
}

/// SEAM-L(r), THE CANCEL CROSSING'S RECORD WRITES: a unit cut by a reload while its op hangs is
/// cancelled on the client-drop path, and the row its plane's `cancel` wrote reaches the kernel's
/// audit chain under the verified principal; its bill is still the drain's. RED: the cancel had no
/// record slot, so a reload-cut unit's row disappeared.
#[tokio::test]
async fn a_reload_cut_units_cancel_writes_its_row() {
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let rows = Arc::new(AuditRows::default());
    r.driver = r.driver.with_audit(rows.clone());
    let r = Arc::new(r);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["hang-row"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let reloader = {
        let r = r.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            r.driver.reload();
        })
    };
    let outcome = cases::drive(&units).await;
    reloader.await.unwrap();
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Failed(
                busbar_contract::caps::StepName::Route,
                busbar_contract::caps::ReasonCode::Drain
            )
        ),
        "{outcome:?}"
    );
    assert_eq!(
        *rows.0.lock().unwrap(),
        vec![(
            "thing.cancel".to_string(),
            "thing:x".to_string(),
            busbar_contract::vocab::OUTCOME_APPLIED,
            common::principal().as_str().to_string(),
        )],
        "the cancel's row, under the kernel's principal"
    );
}

// ── the instance's driver ticket ─────────────────────────────────────────────────────────────────

/// The kernel's host services, with no egress class and no store.
fn services() -> Arc<KernelServices> {
    Arc::new(KernelServices::new())
}

fn driven(every_ns: u64) -> (Arc<Double>, Arc<cases::Book>, PlaneDriver) {
    driven_over(
        Double::default(),
        every_ns,
        services(),
        &serde_yaml::Value::Null,
    )
}

fn driven_over(
    plane: Double,
    every_ns: u64,
    services: Arc<KernelServices>,
    section: &serde_yaml::Value,
) -> (Arc<Double>, Arc<cases::Book>, PlaneDriver) {
    let plane = Arc::new(plane);
    plane.tick_every_ns.store(every_ns, Ordering::SeqCst);
    let book = Arc::new(cases::Book::default());
    let driver = PlaneDriver::new(
        plane.clone(),
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses: cases::statuses(),
            caller_refs: None,
        },
        book.clone(),
        services,
        ("tools", section),
    )
    .expect("the instance is admitted");
    (plane, book, driver)
}

/// The driver mints the instance's ONE driver ticket when it is built (spec :2558, :3315), and
/// gives it back when it goes. RED before K-TICK: no ticket was minted.
#[test]
fn the_driver_mints_the_instance_s_one_driver_ticket_and_recycles_it() {
    let (plane, _book, driver) = driven(0);
    let minted = plane.drivers.lock().unwrap().clone();
    assert_eq!(minted.len(), 1, "one driver ticket per instance");
    drop(driver);
    assert!(
        plane.recycled.lock().unwrap().contains(&minted[0]),
        "the driver ticket goes back with the driver"
    );
}

/// `tick` runs at once, then at the `next_tick_ns` each answer names, never before it; an answer of
/// `0` ends the schedule of a plane with no wake channel (spec :3288, B.3.7); with one it waits on a
/// wake (R-PUSH, the cells below).
#[tokio::test]
async fn the_driver_ticks_at_each_next_tick_and_stops_at_none() {
    let (plane, _book, driver) = driven(20_000_000);
    let run = tokio::time::timeout(Duration::from_millis(130), driver.ticks()).await;
    assert!(run.is_err(), "a schedule that asks again runs on");
    let ticks = plane.ticks.lock().unwrap().clone();
    assert!(ticks.len() >= 3, "ticks: {ticks:?}");
    for w in ticks.windows(2) {
        assert!(
            w[1] >= w[0] + 20_000_000,
            "a tick before its next_tick_ns: {ticks:?}"
        );
    }
    let (plane, _book, driver) = driven(0);
    tokio::time::timeout(Duration::from_secs(5), driver.ticks())
        .await
        .expect("a schedule answered 0 ends");
    assert_eq!(
        plane.ticks.lock().unwrap().len(),
        1,
        "no tick after next_tick_ns = 0"
    );
}

// ── the instance's admission ────────────────────────────────────────────────────────────────────

/// A plane that keeps `approval` records and re-verifies its registrations every hour.
fn declaring() -> Double {
    Double {
        declared: InstanceDecl {
            label: Arc::from("inst"),
            record_kinds: vec!["approval"],
            signing: None,
            scope_kinds: vec![],
            trust_keys: vec![TrustKeyDecl {
                key: "reverify",
                role: TrustRole::ReverifyTtl,
                fingerprint: false,
                default: None,
                mechanisms: &[],
            }],
            record_chains: Vec::new(),
            record_retentions: Vec::new(),
            ticket_prefix: None,
        },
        ..Double::default()
    }
}

/// Services over a memory store, run inline.
fn stored() -> Arc<KernelServices> {
    let store = Arc::new(MemoryStore::new());
    Arc::new(
        KernelServices::new()
            .with_records(Arc::new(Rows(store.clone())), store)
            .with_pool(Arc::new(Inline)),
    )
}

/// A BUILT DRIVER ADMITS ITS INSTANCE (ARCHITECT S7-TICK scope a): its record kinds and trust
/// entries reach the kernel's services, so `records.get` and `trust.due` answer it. RED before:
/// nothing admitted a plane instance, and both answered REFUSED (not admitted).
#[test]
fn a_built_driver_admits_its_instance_to_the_host_services() {
    let services = stored();
    assert_eq!(
        services.trust_due(&instance()).outcome,
        Outcome::Refused,
        "unadmitted"
    );
    let section: serde_yaml::Value = serde_yaml::from_str("peer: {reverify: 1h}").unwrap();
    let (_plane, _book, _driver) = driven_over(declaring(), 0, services.clone(), &section);
    let later: busbar_contract::services::Later = Box::new(|_| {});
    match services.records_get(&instance(), "approval", b"k", later) {
        Ran::Now(s) => assert_ne!(s.outcome, Outcome::Refused, "records.get: {:?}", s.error),
        Ran::Later => {}
    }
    assert_eq!(
        services.trust_due(&instance()).outcome,
        Outcome::Ready,
        "trust.due answers"
    );
}

/// THE KERNEL TICK MARKS DUE BEFORE THE INSTANCE TICKS (ARCHITECT S7-TICK scope c): a registration
/// never verified is listed by `trust.due` once a tick ran, not before.
#[tokio::test]
async fn a_due_subject_shows_in_trust_due_after_a_tick() {
    let services = stored();
    let section: serde_yaml::Value = serde_yaml::from_str("peer: {reverify: 1h}").unwrap();
    let (_plane, _book, driver) = driven_over(declaring(), 0, services.clone(), &section);
    let due = |s: &KernelServices| s.trust_due(&instance()).bytes;
    assert!(due(&services).is_empty(), "nothing is due before a tick");
    tokio::time::timeout(Duration::from_secs(5), driver.ticks())
        .await
        .expect("one tick");
    assert_eq!(due(&services), b"peer".to_vec(), "due after the tick");
}

// ── the kernel's Approve over the trust facts a plane states ────────────────────────────────────

/// One unit at `target` through `driver`: its outcome and, when refused, the body the plane rendered.
async fn approved(driver: &PlaneDriver, target: &str) -> (busbar_contract::caps::Outcome, String) {
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival(target, b"x"), 0);
    let outcome = cases::drive(&units).await;
    let body = units
        .take_rendered()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .unwrap_or_default();
    (outcome, body)
}

/// Whether `outcome` is the kernel's Approve refusing the unit as untrusted.
fn untrusted(outcome: &busbar_contract::caps::Outcome) -> bool {
    matches!(
        outcome,
        busbar_contract::caps::Outcome::Refused(
            busbar_contract::caps::StepName::Approve,
            busbar_contract::caps::ReasonCode::Untrusted
        )
    )
}

/// TRUST IS THE KERNEL'S APPROVE STEP (ARCHITECT 2026-10-06): the plane STATES a counterparty, a
/// capability there and the digest it is offered at; the kernel judges them against its trust book
/// and refuses `untrusted` (the plane told why, `TRUST_*`) when they do not hold. RED arms: an
/// undeclared counterparty (1), one never sighted (2), a quarantined one (3), a capability never
/// approved (4), and one offered at another digest than the one approved (5). A unit stating no
/// trust facts is judged on nothing.
#[tokio::test]
async fn the_kernels_approve_judges_the_trust_facts_a_plane_states() {
    use busbar_kernel::plane_driver::refusal_status;
    let services = stored();
    let section: serde_yaml::Value = serde_yaml::from_str("peer: {reverify: 1h}").unwrap();
    let (_plane, _book, driver) = driven_over(declaring(), 0, services.clone(), &section);
    let refused = |code: u32| {
        format!(
            "refused:{}:untrusted:trust={code}",
            refusal_status(busbar_contract::caps::ReasonCode::Untrusted)
        )
    };

    // No trust facts: nothing judged.
    let (outcome, _) = approved(&driver, "/call").await;
    assert!(!untrusted(&outcome), "{outcome:?}");
    // RED: an undeclared counterparty; one never sighted.
    let (outcome, body) = approved(&driver, "/trusted/stranger").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(1));
    let (outcome, body) = approved(&driver, "/trusted/peer").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(2));

    // Sighted, it is NEW (a first sighting pins nothing) until the operator approves it
    // (`POST /api/v1/admin/trust/approve`): then the counterparty as a whole is trusted.
    let sight = |hash: &'static str| {
        let later: busbar_contract::services::Later = Box::new(|_| {});
        let _ = services.trust_sight(&instance(), "peer", hash, later);
    };
    let decide = |key: &str, decision| services.trust_rule(key, decision).expect("an admitted key");
    use busbar_kernel::trust::book::Ruling;
    sight("h1");
    let (outcome, body) = approved(&driver, "/trusted/peer").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(4), "sighted, never approved");
    decide("inst/peer", Ruling::Approve);
    let (outcome, _) = approved(&driver, "/trusted/peer").await;
    assert!(!untrusted(&outcome), "{outcome:?}");

    // RED: a capability never approved; approved, it serves at its digest alone.
    let (outcome, body) = approved(&driver, "/trusted/peer/cap@d1").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(4));
    let _ = services.trust_sight_item(&instance(), "peer", "cap", "d1");
    decide("inst/peer/cap", Ruling::Approve);
    let (outcome, _) = approved(&driver, "/trusted/peer/cap@d1").await;
    assert!(!untrusted(&outcome), "{outcome:?}");
    let (outcome, body) = approved(&driver, "/trusted/peer/cap@d2").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(5));
    let (outcome, _) = approved(&driver, "/trusted/peer/cap").await;
    assert!(!untrusted(&outcome), "no digest stated: its last sighting");

    // An item stated with no digest: unknown until the plane's re-fetch sights it (6, a 404's
    // case), known and ungranted after (4, a 403's case), served once approved at its sighting,
    // and changed once a re-fetch sees another digest (5).
    let (outcome, body) = approved(&driver, "/trusted/peer/tool").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(6));
    let sighted = services.trust_sight_item(&instance(), "peer", "tool", "t1");
    assert_eq!(
        sighted.value,
        busbar_contract::abi::host::service::TRUST_NEW
    );
    let (outcome, body) = approved(&driver, "/trusted/peer/tool").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(4));
    decide("inst/peer/tool", Ruling::Approve);
    let serves = |item: &str| {
        services
            .trust_serves(&instance(), "peer", Some(item), None)
            .value
    };
    assert_eq!(
        serves("tool"),
        busbar_contract::abi::host::service::DISTRUST_NONE
    );
    let (outcome, _) = approved(&driver, "/trusted/peer/tool").await;
    assert!(!untrusted(&outcome), "{outcome:?}");
    let _ = services.trust_sight_item(&instance(), "peer", "tool", "t2");
    assert_eq!(
        serves("tool"),
        busbar_contract::abi::host::service::DISTRUST_CHANGED
    );
    assert_eq!(
        serves("never-seen"),
        busbar_contract::abi::host::service::DISTRUST_UNKNOWN_ITEM
    );

    // RED: a sighting that drifts quarantines the counterparty, whatever was approved, until the
    // operator approves it again; a revoke refuses it.
    sight("h2");
    let (outcome, body) = approved(&driver, "/trusted/peer/cap@d1").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(3));
    decide("inst/peer", Ruling::Approve);
    let (outcome, _) = approved(&driver, "/trusted/peer/cap@d1").await;
    assert!(!untrusted(&outcome), "re-approved: {outcome:?}");
    decide("inst/peer", Ruling::Revoke);
    let (outcome, body) = approved(&driver, "/trusted/peer/cap@d1").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(4), "revoked");
    // Unknown keys are no keys.
    assert_eq!(
        services.trust_rule("inst/stranger", Ruling::Approve),
        Err(busbar_kernel::host_services::TrustRefused::NoSuchKey)
    );
}

/// THE GRANT IS JUDGED BEFORE THE TRUST FACTS (ruling (a), coordinator 2026-10-07: the ordered
/// gate is identity, grant, then the counterparty's standing). A unit whose caller the
/// deployment's Approve refuses (`scope_denied`) is refused for that, at Approve, even when the
/// counterparty it states is one the book does not trust: a grant refusal never tells the caller
/// the counterparty's trust state. RED before the order: the unit was refused `untrusted`. The
/// control: the same untrusted facts under a deployment that grants are refused `untrusted`.
#[tokio::test]
async fn the_kernels_approve_judges_the_grant_before_the_trust_facts() {
    use busbar_contract::caps::{Outcome, ReasonCode, StepName};
    let services = stored();
    let section: serde_yaml::Value = serde_yaml::from_str("peer: {reverify: 1h}").unwrap();
    let (_plane, _book, driver) = driven_over(declaring(), 0, services.clone(), &section);
    let (steps, far, caller) = (
        common::TestUnits::refusing(StepName::Approve, ReasonCode::ScopeDenied),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/trusted/stranger", b"x"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert_eq!(
        outcome,
        Outcome::Refused(StepName::Approve, ReasonCode::ScopeDenied),
        "the grant's refusal, not the counterparty's standing"
    );
    let body = units
        .take_rendered()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .unwrap_or_default();
    assert!(!body.contains("untrusted"), "{body}");
    let (outcome, _) = approved(&driver, "/trusted/stranger").await;
    assert!(untrusted(&outcome), "granted, the book judges: {outcome:?}");
}

// ── the plane's own work bounds (its section's reserved `work:`) ────────────────────────────────

/// A PLANE'S `work:` BOUNDS OVERRIDE THE HOST'S (spec POOLS-VERBS: the reserved `work: {max_live,
/// retain_s}` sub-key): the instance's section binds its bounds at admission (a key it leaves out is
/// the host's), `work.open` is refused at the plane's own `max_live`, an instance that states none
/// keeps the host's, and `work:` is never read as a registration.
#[test]
fn a_planes_work_section_overrides_the_hosts_work_bounds() {
    use busbar_kernel::host_units::UnitRecord;
    use busbar_kernel::host_work::{refusal, WorkBounds};
    let store = Arc::new(MemoryStore::new());
    let host = WorkBounds {
        max_live: 3,
        retain_ms: 300_000,
    };
    let services = Arc::new(
        KernelServices::new()
            .with_records(Arc::new(Rows(store.clone())), store)
            .with_pool(Arc::new(Inline))
            .with_work_bounds(host),
    );
    let section: serde_yaml::Value =
        serde_yaml::from_str("work: {max_live: 1}\npeer: {reverify: 1h}").unwrap();
    let (_plane, _book, _driver) = driven_over(declaring(), 0, services.clone(), &section);
    assert_eq!(
        services.work_bounds_of("inst"),
        WorkBounds {
            max_live: 1,
            retain_ms: 300_000
        },
        "the plane's max_live, the host's retention"
    );
    assert_eq!(
        services.work_bounds_of("unbound"),
        host,
        "no work: is the host's"
    );
    services.units().admitted(1, UnitRecord::default());
    let open = |record: &'static [u8]| {
        let slot: Arc<std::sync::Mutex<Option<busbar_contract::services::Stored>>> = Arc::default();
        let mine = Arc::clone(&slot);
        let later: busbar_contract::services::Later =
            Box::new(move |s| *mine.lock().unwrap() = Some(s));
        match services.work_open(&instance(), Some(1), "approval", record, later) {
            Ran::Now(s) => s,
            Ran::Later => slot.lock().unwrap().take().expect("answered"),
        }
    };
    assert_eq!(open(b"first").outcome, Outcome::Ready);
    let second = open(b"second");
    assert_eq!(
        (second.outcome, second.error),
        (Outcome::Refused, refusal::AT_BOUND),
        "refused at the plane's own max_live of 1, under the host's 3"
    );
}

/// A SECTION THAT MISSTATES ITS `work:` BOUNDS REFUSES THE INSTANCE, naming the key.
#[test]
fn a_misstated_work_section_refuses_the_instance() {
    for bad in [
        "work: 4",
        "work: {max_live: 0}",
        "work: {max_live: many}",
        "work: {retain_s: -1}",
        "work: {evict: true}",
    ] {
        let section: serde_yaml::Value = serde_yaml::from_str(bad).unwrap();
        let refused = PlaneDriver::new(
            Arc::new(declaring()),
            DriverConfig {
                caps: BufferCaps::default(),
                op_classes: vec![OpClassId::new("call")],
                status_of: refusal_status,
                refusal_statuses: cases::statuses(),
                caller_refs: None,
            },
            Arc::new(cases::Book::default()),
            stored(),
            ("tools", &section),
        )
        .err()
        .unwrap_or_else(|| panic!("{bad}: refused"));
        assert!(refused.starts_with("`tools.work`"), "{bad}: {refused}");
    }
}

// ── write-behind (ruling H2 U10) ────────────────────────────────────────────────────────────────

#[path = "support/plane_driver_write_behind.rs"]
mod write_behind;

/// RED (abi/plane "A refused arrival"): an arrival the plane refused in its own words is rendered
/// by the plane's `refusal` with those words as its text and cause REFUSAL_ARRIVE, at the status
/// the plane stated; without words it is rendered in the kernel's (`a_refused_arrival_wears_...`).
#[tokio::test]
async fn a_refused_arrival_is_rendered_in_the_planes_own_words() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], &[]),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/refuse-words", b"x"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Refused(
                busbar_contract::caps::StepName::Decode,
                busbar_contract::caps::ReasonCode::DecodeFailed
            )
        ),
        "{outcome:?}"
    );
    assert!(far.sent().is_empty());
    let rendered = units.take_rendered().expect("the refusal is rendered");
    assert_eq!(rendered.status, 400);
    let body = String::from_utf8_lossy(&rendered.body).into_owned();
    assert!(
        body.starts_with("words:refused:400:the body is not a document:7@"),
        "{body}"
    );
}

// ── a refusal about an entry, and its order against admission (abi/plane rule 6) ────────────────

/// Units whose door refuses: the caller's group has no requests left.
fn spent_caller() -> common::TestUnits {
    common::TestUnits {
        refuse_at: Some((
            busbar_contract::caps::StepName::Admit,
            busbar_contract::caps::ReasonCode::RateLimited,
        )),
        ..common::TestUnits::passing()
    }
}

/// The plane's own rendering of its refusal about the entry: its status, and its code beside the
/// unit.
fn the_planes_refusal(rendered: &busbar_kernel::plane_driver::Rendered) -> bool {
    let body = String::from_utf8_lossy(&rendered.body);
    rendered.status == ENTRY_REFUSED_STATUS && body.contains(&format!(":{ENTRY_REFUSED}@"))
}

/// RULE 6 AS IT WAS (flag `0`): a refusal about an entry is rendered BEFORE admission. A caller
/// whose group has no requests left is answered the plane's refusal, never the 429: the door is
/// never asked, so nothing is counted or charged, and nothing is sent.
#[tokio::test]
async fn a_held_refusal_is_rendered_before_admission_and_charges_nothing() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (steps, far, caller) = (
        spent_caller(),
        cases::Far::new(&["ok"], &[]),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/refuse-entry", b"x"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Refused(
                _,
                busbar_contract::caps::ReasonCode::DecodeFailed
            )
        ),
        "{outcome:?}"
    );
    let rendered = units.take_rendered().expect("the refusal is rendered");
    assert!(the_planes_refusal(&rendered), "{rendered:?}");
    assert!(
        !steps
            .calls
            .lock()
            .unwrap()
            .contains(&busbar_contract::caps::StepName::Admit),
        "the door was never asked: nothing counted, nothing charged"
    );
    assert!(far.sent().is_empty());
}

/// RED (`REFUSED_AFTER_ADMISSION`, the previous release's order): a refusal about an entry the
/// plane states after admission waits for the entry's admission, and an admission refusal WINS.
/// The caller whose group has no requests left is answered admission's 429; the plane's refusal
/// never renders. RED before the flag was read: the plane's refusal, rendered before admission.
#[tokio::test]
async fn a_refusal_after_admission_loses_to_admissions_own_refusal() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (steps, far, caller) = (
        spent_caller(),
        cases::Far::new(&["ok"], &[]),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/refuse-entry-after", b"x"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Refused(
                busbar_contract::caps::StepName::Admit,
                busbar_contract::caps::ReasonCode::RateLimited
            )
        ),
        "admission's refusal, not the plane's: {outcome:?}"
    );
    let rendered = units
        .take_rendered()
        .expect("admission's refusal is rendered");
    assert_eq!(rendered.status, 429);
    assert!(!the_planes_refusal(&rendered), "{rendered:?}");
    assert!(far.sent().is_empty());
}

/// RED (`REFUSED_AFTER_ADMISSION`): a caller within its limits is admitted, and then answered the
/// plane's refusal in the plane's status and code, with no walk (nothing sent), no hook (a
/// gate-first binder is never asked) and no meter; the fee admission charged is refunded at the
/// unit's end on the refusal's status, so the unit nets no charge. RED before the flag was read:
/// the door was never asked.
#[tokio::test]
async fn a_refusal_after_admission_within_limits_is_the_planes_and_nets_no_charge() {
    use busbar_kernel::config::groups::{ExhaustionMode, GroupCfg};
    use busbar_kernel::governance::{GovState, WINDOW_TOTAL};
    use busbar_kernel::plane_driver::{EndPost, FeeRefund, PlaneMoney, UnitMoney};
    struct NoPost;
    impl EndPost for NoPost {
        fn post(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
    }
    const AT: u64 = 1_700_000_000;
    // WHAT ADMISSION HOLDS for this unit, as the composition root's door opens it on a pass: the
    // request fee charged by the governance book's one check-then-charge, and the unit's money
    // facts open on the money steps, the plane's report its one fee decider.
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("gov"));
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(NoPost)));
    let groups = std::collections::BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: true,
            ..Default::default()
        },
    )]);
    let card = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            output_utok: 1.0,
            ..Default::default()
        },
    )]);
    let cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
        Some(&card),
        5,
        &groups,
    ));
    let key = Arc::new(busbar_contract::records::VirtualKey {
        id: "k".into(),
        generation_hash: "h:k".into(),
        name: "k".into(),
        enabled: true,
        group: Some("g".into()),
        revision: 1,
        ..Default::default()
    });
    let spend = || {
        gov.derived_bucket_usage(&cost, &key.id, WINDOW_TOTAL, true, AT)
            .expect("usage")
    };
    let grant = gov
        .try_admit(&cost, &key, "", AT)
        .expect("admitted, the fee charged");
    let unit = common::ctx(7).key;
    money.open(
        unit,
        UnitMoney {
            key: key.clone(),
            cost: cost.clone(),
            pool: String::new(),
            lane: "m".into(),
            classes: Arc::from(vec![busbar_contract::plane::PER_REQUEST.to_string()]),
            arrived: AT,
            mode: ExhaustionMode::FinishUnit,
            fee: FeeRefund::PlaneFeeUnits(Arc::from(vec![0u32])),
            charge: grant.charge().clone(),
        },
    );
    assert_eq!(spend().spend_cents, 5, "admission charged its fee");

    let r = rig(
        Way::Double,
        BufferCaps::default(),
        cases::Book::forwarding(money.clone()),
    );
    let gate = Arc::new(Refuses {
        abstains: true,
        ..Refuses::default()
    });
    let binder = Arc::new(GateFirst {
        gate: Arc::clone(&gate),
        asked: Mutex::new(Vec::new()),
    });
    let driver = r.driver.with_hooks(binder.clone());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], &[]),
        cases::Caller::default(),
    );
    let units = driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/refuse-entry-after", b"x"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Failed(
                _,
                busbar_contract::caps::ReasonCode::DecodeFailed
            )
        ),
        "refused after its admission, through the admitted finish: {outcome:?}"
    );
    let calls = steps.calls.lock().unwrap().clone();
    assert!(
        calls.contains(&busbar_contract::caps::StepName::Admit),
        "admission ran: {calls:?}"
    );
    assert!(
        !calls.contains(&busbar_contract::caps::StepName::Meter),
        "nothing metered: {calls:?}"
    );
    assert!(far.sent().is_empty(), "no walk: nothing sent");
    assert_eq!(gate.calls.load(Ordering::SeqCst), 0, "no hook ran");
    assert!(binder.asked.lock().unwrap().is_empty(), "no hook was bound");
    let rendered = units
        .take_rendered()
        .expect("the plane's refusal is rendered");
    assert!(the_planes_refusal(&rendered), "{rendered:?}");
    // The unit's end, on the status its caller was answered: the fee comes back.
    money.settle_end(unit, rendered.status);
    let usage = spend();
    assert_eq!(
        (usage.spend_cents, usage.tokens),
        (0, 0),
        "nothing net-charged, nothing ledgered"
    );
}

// ── a unit served as a session (ARCHITECT round 5 Q-L3B-K6-HTTP (a)) ───────────────────────────

/// A request's caller side, as the composition root's ingress caller is: its read yields the
/// arrival's body once, then nothing until the caller goes away, when its side ends.
struct OnceCaller {
    body: Mutex<Option<Vec<u8>>>,
    head: Mutex<Option<u32>>,
    heard: Mutex<Vec<u8>>,
    gone: tokio::sync::Notify,
}

impl OnceCaller {
    fn new(body: &[u8]) -> Self {
        OnceCaller {
            body: Mutex::new(Some(body.to_vec())),
            head: Mutex::new(None),
            heard: Mutex::new(Vec::new()),
            gone: tokio::sync::Notify::new(),
        }
    }

    fn heard(&self) -> String {
        String::from_utf8_lossy(&self.heard.lock().unwrap()).into_owned()
    }
}

impl busbar_kernel::plane_driver::CallerEnd for OnceCaller {
    fn head(&self, status: u32, _fields: Vec<(Vec<u8>, Vec<u8>)>) {
        *self.head.lock().unwrap() = Some(status);
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        self.heard.lock().unwrap().extend_from_slice(bytes);
        true
    }
}

impl busbar_kernel::plane_driver::SessionCaller for OnceCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        let first = self.body.lock().unwrap().take();
        if first.is_some() {
            return first;
        }
        self.gone.notified().await;
        None
    }
}

/// A `ROUTE_SESSION` ARRIVAL IS DRIVEN AS A SESSION (ARCHITECT round 5 Q-L3B-K6-HTTP (a)): the
/// loop's route leg is the duplex session, its caller leg the unit's own caller side, whose read
/// yields the arrival's body ONCE (one caller piece, on the unit's stream); the instance's tick
/// owes the session output, `drive` names it, and the session collects it on its caller-side ticket
/// (the keepalive, every tick) until the caller goes away; nothing dialled, and a session its plane
/// answers itself bills nothing (as a local request unit). RED before
/// the route leg switched: the unit was walked as a request, and with no member its walk was
/// exhausted (refused, nothing heard).
#[tokio::test]
async fn a_route_session_arrival_is_driven_as_a_session_whose_caller_leg_is_the_units() {
    use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
    use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};
    let (plane, book, driver) = driven(5_000_000);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&[], &[]),
        OnceCaller::new(b"hello"),
    );
    let units = driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/session", b"hello"),
        0,
    );
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        busbar_contract::caps::Canary::new(),
        LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = common::cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };
    let ctx = common::ctx(7);
    let unit = run_unit_async(&kernel, &units, &ctx, run, &units);
    // The caller goes away once it heard the session open and three keepalives.
    let leaves = async {
        while caller.heard().matches("keepalive;").count() < 3 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        caller.gone.notify_one();
        std::future::pending::<()>().await;
    };
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            ended = unit => ended,
            () = async { tokio::join!(driver.ticks(), driver.drives()); } => panic!("the schedule ran on"),
            () = leaves => unreachable!(),
        }
    })
    .await
    .expect("the session collected the tick's output and ended with its caller");
    let outcome = match ended {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    };
    assert!(
        matches!(outcome, busbar_contract::caps::Outcome::Completed),
        "{outcome:?}"
    );
    assert_eq!(*caller.head.lock().unwrap(), Some(200));
    let heard = caller.heard();
    assert!(heard.starts_with("open:hello"), "{heard}");
    assert_eq!(
        plane.sessions.read.lock().unwrap().clone(),
        vec![(7, b"hello".to_vec())],
        "the caller leg yielded the arrival's body once, on the unit's stream"
    );
    assert!(plane.sessions.collects.load(Ordering::SeqCst) >= 3);
    assert!(
        far.sent().is_empty(),
        "a session the plane answers dials nothing"
    );
    assert_eq!(
        book.sessions_ended.load(Ordering::SeqCst),
        0,
        "a session its plane answers itself (ROUTE_LOCAL) tells the money seam nothing"
    );
}

// ── the gate-first hook order (`TAIL_HOOKS_GATED`; spec Part 3 section 12 "Hooks") ────────────

/// A decision gate that refuses every request at 451 with its own words (or, `abstains`, lets
/// every request by), counting its calls.
#[derive(Default)]
struct Refuses {
    calls: AtomicU32,
    abstains: bool,
}

#[async_trait::async_trait]
impl busbar_contract::hooks::RoutingPolicy for Refuses {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _candidates: &[busbar_contract::hooks::Candidate<'_>],
        _ctx: &busbar_contract::hooks::RoutingContext<'_>,
        _budget: Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.abstains {
            return Ok(busbar_contract::hooks::RoutingDecision::Abstain);
        }
        Ok(busbar_contract::hooks::RoutingDecision::Reject {
            status: 451,
            message: "refused at the entry".into(),
        })
    }

    fn name(&self) -> &'static str {
        "entry-gate"
    }
}

/// A gate-first binder attaching `gate` to every entry, recording the entries it was asked for.
struct GateFirst {
    gate: Arc<Refuses>,
    asked: Mutex<Vec<String>>,
}

impl busbar_kernel::plane_driver::HookBinder for GateFirst {
    fn bind(
        &self,
        _bind: &busbar_kernel::plane_driver::Bind<'_>,
    ) -> Option<busbar_kernel::plane_driver::UnitHooks> {
        panic!("a gate-first plane binds no routed hooks")
    }

    fn order(&self) -> busbar_kernel::plane_driver::HookOrder {
        busbar_kernel::plane_driver::HookOrder::Gated
    }

    fn bind_gated(
        &self,
        container: &str,
        _principal: Option<&str>,
    ) -> Option<busbar_kernel::plane_driver::GatedHooks> {
        self.asked.lock().unwrap().push(container.to_string());
        Some(busbar_kernel::plane_driver::GatedHooks {
            request_id: 7,
            gates: vec![(
                0,
                busbar_kernel::hooks::ResolvedPolicy::Policy {
                    policy: Arc::clone(&self.gate)
                        as Arc<dyn busbar_contract::hooks::RoutingPolicy>,
                    on_error: busbar_kernel::config::PolicyOnError::Reject,
                    on_error_chain: Vec::new(),
                    timeout: Duration::from_secs(5),
                    send_prompt: false,
                    send_user: false,
                    on_empty: busbar_kernel::config::PolicyOnError::Reject,
                },
            )],
            rewrites: Vec::new(),
            key: None,
            scan: None,
        })
    }
}

/// THE GATE-FIRST ORDER: a plane whose binder states it has its entry's decision gate screen the
/// unit before the door (ARCHITECT ruling, Mode B); a refusal stops the unit at the gate's own
/// status and words (HookVeto, refused at Approve's seat), the binder is asked for the entry the
/// plane's projection names, the door is never asked (nothing admitted, nothing counted) and
/// nothing is sent.
#[tokio::test]
async fn a_gate_first_plane_screens_its_entry_before_the_far_end_and_stops_at_the_gates_status() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let gate = Arc::new(Refuses::default());
    let binder = Arc::new(GateFirst {
        gate: Arc::clone(&gate),
        asked: Mutex::new(Vec::new()),
    });
    let driver = r.driver.with_hooks(binder.clone());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], &[]),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Refused(
                busbar_contract::caps::StepName::Approve,
                busbar_contract::caps::ReasonCode::HookVeto
            )
        ),
        "{outcome:?}"
    );
    assert_eq!(
        gate.calls.load(Ordering::SeqCst),
        1,
        "the gate screened once"
    );
    assert!(
        !steps
            .calls
            .lock()
            .unwrap()
            .contains(&busbar_contract::caps::StepName::Admit),
        "a veto admits nothing: the door was never asked"
    );
    // The entry the kernel recorded at decode (this double's `arrive` names none, and its
    // projection names the same).
    assert_eq!(*binder.asked.lock().unwrap(), vec![String::new()]);
    assert!(far.sent().is_empty(), "nothing reached the far end");
    let rendered = units.take_rendered().expect("the veto is rendered");
    assert_eq!(rendered.status, 451);
}

/// RED (ARCHITECT ruling, Mode B order): an OVER-BUDGET caller of a gate-first plane is answered
/// the gate's refusal, not the door's: the gate screens before the door, which is never asked.
#[tokio::test]
async fn a_gate_first_planes_over_budget_caller_gets_the_gates_answer_before_the_budgets() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let gate = Arc::new(Refuses::default());
    let binder = Arc::new(GateFirst {
        gate: Arc::clone(&gate),
        asked: Mutex::new(Vec::new()),
    });
    let driver = r.driver.with_hooks(binder);
    let steps = common::TestUnits {
        refuse_at: Some((
            busbar_contract::caps::StepName::Admit,
            busbar_contract::caps::ReasonCode::OverBudget,
        )),
        ..common::TestUnits::passing()
    };
    let (far, caller) = (cases::Far::new(&["ok"], &[]), cases::Caller::default());
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Refused(
                busbar_contract::caps::StepName::Approve,
                busbar_contract::caps::ReasonCode::HookVeto
            )
        ),
        "the gate's answer, not the budget's: {outcome:?}"
    );
    assert_eq!(units.take_rendered().expect("rendered").status, 451);
    assert!(!steps
        .calls
        .lock()
        .unwrap()
        .contains(&busbar_contract::caps::StepName::Admit));
}

/// A gate-first plane whose gate lets the unit by is admitted AFTER it (the door is asked once the
/// screen passed) and served; the gate is not asked again at the route leg.
#[tokio::test]
async fn a_gate_first_planes_passing_screen_reaches_the_door_and_the_far_end_once() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let gate = Arc::new(Refuses {
        abstains: true,
        ..Refuses::default()
    });
    let binder = Arc::new(GateFirst {
        gate: Arc::clone(&gate),
        asked: Mutex::new(Vec::new()),
    });
    let driver = r.driver.with_hooks(binder);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], &[]),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
    let outcome = cases::drive(&units).await;
    assert!(
        !matches!(outcome, busbar_contract::caps::Outcome::Refused(..)),
        "{outcome:?}"
    );
    assert_eq!(
        gate.calls.load(Ordering::SeqCst),
        1,
        "screened once, at the screen"
    );
    assert!(steps
        .calls
        .lock()
        .unwrap()
        .contains(&busbar_contract::caps::StepName::Admit));
    assert!(!far.sent().is_empty(), "the far end was reached");
}

/// A UNIT ITS PLANE ANSWERS AT ITS SCOPE'S ONE ENTRY (`ROUTE_SCOPE_LOCAL`, COORDINATOR ruling
/// 2026-10-07), plane-neutral: the steps resolve the one entry the principal's grant reaches
/// (`DriverSteps::resolved`), and the driver walks NO route for it, whatever far end it was handed:
/// the far end is never asked for a member and nothing is sent, and the caller's body reaches the
/// plane once, with no attempt (`attempt_no` `0`), its `OnPieceIn::member` the resolved entry, and
/// the plane's own answer is the caller's. A unit the plane sends toward a far end anyway has none
/// and fails unreachable, still undialled. Steps that resolve zero or several entries refuse it
/// `no_destination` at admission, before any piece. RED before the driver skipped the walk: the
/// far end was asked for a member (and, had the plane sent, dialled).
#[tokio::test]
async fn a_scope_local_unit_is_answered_at_its_resolved_entry_with_no_walk() {
    use busbar_contract::caps::{Outcome, ReasonCode, StepName};
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let steps = common::TestUnits {
        resolved: Some(b"entry-a".to_vec()),
        ..common::TestUnits::passing()
    };
    let (far, caller) = (
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/scope-local", b"hi"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");
    assert_eq!(far.picks(), 0, "no route is walked");
    assert!(far.sent().is_empty(), "no egress");
    assert_eq!(
        r.plane.scope_members.lock().unwrap().clone(),
        vec![(0, b"entry-a".to_vec())],
        "the body, once, with no attempt, its member the resolved entry"
    );
    assert_eq!(caller.text(), "hi", "the plane's own answer");

    // The plane sends it toward a far end: there is none to send it to.
    let (far, caller) = (
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/scope-local-far", b"hi"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            Outcome::Failed(_, ReasonCode::DestinationUnreachable)
                | Outcome::Refused(_, ReasonCode::DestinationUnreachable)
        ),
        "{outcome:?}"
    );
    assert_eq!((far.picks(), far.sent().len()), (0, 0), "still undialled");

    // Zero or several reachable entries: the steps refuse it `no_destination` before any piece.
    r.plane.scope_members.lock().unwrap().clear();
    let unresolved = common::TestUnits {
        refuse_at: Some((StepName::Admit, ReasonCode::NoDestination)),
        ..common::TestUnits::passing()
    };
    let (far, caller) = (
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &unresolved,
        &far,
        &caller,
        cases::arrival("/scope-local", b"hi"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(
            outcome,
            Outcome::Refused(StepName::Admit, ReasonCode::NoDestination)
        ),
        "{outcome:?}"
    );
    assert_eq!((far.picks(), far.sent().len()), (0, 0), "undialled");
    assert!(
        r.plane.scope_members.lock().unwrap().is_empty(),
        "no piece reached the plane"
    );
}

/// RED (SEAM-4l additions): a plane that frames messages hands the caller's side each message's END
/// (`EMIT_MESSAGE_END`), one per far-end piece however its bytes were written, and closes its reply
/// with a FINAL status (`EMIT_FINAL_STATUS`): the status number, its message and its details
/// bytes reach the caller's side whole; a plane that does neither hands neither.
#[tokio::test]
async fn a_planes_message_boundaries_and_final_status_reach_the_callers_side() {
    for (member, framed) in [("framed", true), ("ok", false)] {
        let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
        let (steps, far, caller) = (
            common::TestUnits::passing(),
            cases::Far::new(&[member], cases::CHUNKS),
            cases::Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, cases::arrival("/call", b"p"), 0);
        assert!(
            matches!(
                cases::drive(&units).await,
                busbar_contract::caps::Outcome::Completed
            ),
            "{member}"
        );
        let boundaries = caller.boundaries.load(Ordering::SeqCst);
        let finale = caller.finale.lock().unwrap().clone();
        if framed {
            assert_eq!(
                boundaries,
                cases::CHUNKS.len() as u64,
                "one end per far-end piece"
            );
            assert_eq!(finale, Some((5, b"not here".to_vec(), vec![1, 2])));
        } else {
            assert_eq!(boundaries, 0);
            assert_eq!(finale, None);
        }
        assert_eq!(
            caller.text(),
            "hello far end",
            "{member}: the bytes are unchanged"
        );
    }
}

/// SEAM-L(o), (p): A KERNEL REFUSAL'S RECORD WRITES AND THE VETOING HOOK. A gate's veto hands the
/// plane's `refusal` the vetoing hook's name, which the plane renders (predev's
/// `{"reason":"hook_rejected","hook":<name>}`), and the refusal's `RECORD_AUDIT` write is one
/// rejected row on the kernel's audit chain under the verified principal. RED: the refusal had no
/// record slot and named no hook.
#[tokio::test]
async fn a_vetoed_units_refusal_names_the_hook_and_writes_its_rejected_row() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let rows = Arc::new(AuditRows::default());
    let binder = Arc::new(GateFirst {
        gate: Arc::new(Refuses::default()),
        asked: Mutex::new(Vec::new()),
    });
    let driver = r.driver.with_hooks(binder).with_audit(rows.clone());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], &[]),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
    let _ = cases::drive(&units).await;
    let rendered = units.take_rendered().expect("the veto is rendered");
    let body = String::from_utf8_lossy(&rendered.body).to_string();
    assert!(body.ends_with(":hook=entry-gate"), "{body}");
    assert_eq!(
        *rows.0.lock().unwrap(),
        vec![(
            "thing.call".to_string(),
            "thing:x".to_string(),
            busbar_contract::vocab::OUTCOME_REJECTED,
            common::principal().as_str().to_string(),
        )]
    );
}

// ── a refusal handed to the plane as a piece first (`TAIL_REFUSED_PIECE`) ───────────────────────

/// A far end whose walk picks `m0` first when it `sends` (the attempt's request goes out and
/// nothing comes back: its credential no longer resolves, or its connection fails), then answers
/// `then`: the walk's credential refusal, or its exhaustion terminal. Without `sends` the walk
/// answers `then` at once and no request goes out. `unsent` is why nothing left, as the walk says
/// it (`FarEnd::unsent`): `None`, the walk names none.
struct Gone {
    unsent: Option<busbar_contract::abi::plane::RefusalCode>,
    sends: bool,
    then: busbar_kernel::plane_driver::Pick,
}

impl busbar_kernel::plane_driver::FarEnd for Gone {
    fn member<'a>(
        &'a self,
        _: &'a busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        attempt_no: u32,
    ) -> impl Future<Output = busbar_kernel::plane_driver::Pick> + Send + 'a {
        use busbar_kernel::plane_driver::Pick;
        let pick = if attempt_no == 1 && self.sends {
            Pick::Member {
                name: "m0".to_string(),
                pool: "pool-a".to_string(),
                passthrough: false,
                provider: "acme".to_string(),
            }
        } else {
            self.then.clone()
        };
        async move { pick }
    }

    async fn send(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        _: busbar_kernel::plane_driver::OutboundRequest,
    ) -> bool {
        false
    }

    async fn next(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
    ) -> Option<busbar_kernel::plane_driver::FarPiece> {
        None
    }

    async fn write(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        _: busbar_kernel::plane_driver::OutboundRequest,
    ) -> bool {
        false
    }

    fn unsent(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
    ) -> Option<busbar_contract::abi::plane::RefusalCode> {
        self.unsent
    }
}

/// Run one unit over `far` through the one loop; its outcome, and what its meter accrued.
async fn drive_gone(
    units: &busbar_kernel::plane_driver::PlaneUnits<'_, common::TestUnits, Gone, cases::Caller>,
) -> (busbar_contract::caps::Outcome, u64) {
    use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
    use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        busbar_contract::caps::Canary::new(),
        LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = common::cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };
    let outcome = match run_unit_async(&kernel, units, &common::ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    };
    (outcome, meter.total())
}

/// What one unit over [`Gone`] came to, on a driver that `takes` the refused piece or not: its
/// outcome, the reasons of the refused pieces the plane was handed, the `refused` record as the
/// host holds it, and whether anything the refused piece emitted reached the caller; the caller's
/// rendered refusal, and what the unit's meter accrued.
struct Came {
    outcome: busbar_contract::caps::Outcome,
    refused: Vec<u32>,
    written: Stored,
    leaked: bool,
    body: String,
    charged: u64,
}

async fn came(far: Gone, takes: bool) -> Came {
    let s = records();
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.driver = r.driver.with_records(Arc::clone(&s), instance());
    if takes {
        r.driver = r.driver.with_refused_piece();
    }
    let (steps, caller) = (common::TestUnits::passing(), cases::Caller::default());
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/x", b"x"), 0);
    let (outcome, charged) = drive_gone(&units).await;
    let rendered = units.take_rendered().expect("the refusal is rendered");
    let body = String::from_utf8_lossy(&rendered.body).into_owned();
    assert!(body.starts_with("refused:"), "takes={takes}: {body}");
    let leaked = caller.text().contains("not-for-the-caller") || caller.status() == Some(299);
    let refused = r.plane.refused.lock().unwrap().clone();
    Came {
        outcome,
        refused,
        written: get(&s, b"refused"),
        leaked,
        body,
        charged,
    }
}

/// A UNIT REFUSED `credential_unavailable` IS HANDED TO A PLANE WHOSE TAIL TAKES IT AS A PIECE
/// FIRST (`TAIL_REFUSED_PIECE`, `PlaneDriver::with_refused_piece`): a `FROM_KERNEL` piece flagged
/// `PIECE_REFUSED` and last, carrying the reason, on the unit's own ticket; its record writes are
/// written, nothing it emits reaches the caller, and the unit is then refused and rendered by
/// `refusal` as before. RED arm: a plane without the bit is sent no such piece, writes nothing, and
/// is refused exactly as today.
#[tokio::test]
async fn a_credential_refusal_is_handed_as_a_piece_first_only_to_a_plane_that_takes_it() {
    use busbar_contract::caps::{Outcome as Unit, ReasonCode, StepName};
    let code = busbar_contract::abi::plane::reason_code(ReasonCode::CredentialUnavailable);
    let gone = || Gone {
        unsent: None,
        sends: true,
        then: busbar_kernel::plane_driver::Pick::Refused(ReasonCode::CredentialUnavailable),
    };
    for takes in [true, false] {
        let c = came(gone(), takes).await;
        assert!(
            matches!(
                c.outcome,
                Unit::Failed(StepName::Route, ReasonCode::CredentialUnavailable)
            ),
            "takes={takes}: the unit ends as a credential refusal does without the bit: {:?}",
            c.outcome
        );
        assert!(
            !c.leaked,
            "takes={takes}: nothing the refused piece emitted reached the caller"
        );
        if takes {
            assert_eq!(c.refused, vec![code]);
            assert_eq!(
                (c.written.value, c.written.bytes),
                (svc::FOUND, code.to_string().into_bytes()),
                "the refused piece's record write is written"
            );
        } else {
            assert!(c.refused.is_empty(), "no refused piece");
            assert_eq!(c.written.value, svc::ABSENT, "nothing written");
        }
    }
}

/// A UNIT WHOSE REQUEST WENT OUT AND WHOSE WALK THEN ENDED WITH NO MEMBER LEFT (its connection
/// failed, or closed unanswered) is handed to a plane whose tail takes it as a refused piece first,
/// naming the reason it is refused for (`breaker_open`, the walk's exhaustion terminal); so is a
/// walk that exhausted before any request went out (R-REJECTED, coordinator 2026-10-07, extends
/// gap-2: the plane opens the unit's task and settles it `rejected`). RED arm: a plane without the
/// bit is sent no such piece, in either case, and its unit ends exactly as the bit's does.
#[tokio::test]
async fn a_walk_that_ends_after_a_request_went_out_is_handed_as_a_piece_first() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::plane_driver::Pick;
    let code = busbar_contract::abi::plane::reason_code(ReasonCode::BreakerOpen);
    let exhausted = || Pick::Exhausted {
        status: 503,
        retry_after: Some(2),
        detail: "The service is temporarily overloaded. Please retry shortly.",
    };
    let taken = came(
        Gone {
            unsent: None,
            sends: true,
            then: exhausted(),
        },
        true,
    )
    .await;
    let without = came(
        Gone {
            unsent: None,
            sends: true,
            then: exhausted(),
        },
        false,
    )
    .await;
    assert_eq!(
        format!("{:?}", taken.outcome),
        format!("{:?}", without.outcome),
        "the unit ends the same with the bit and without it"
    );
    assert_eq!(taken.refused, vec![code]);
    assert_eq!(
        (taken.written.value, taken.written.bytes),
        (svc::FOUND, code.to_string().into_bytes()),
        "the refused piece's record write is written"
    );
    assert!(!taken.leaked && !without.leaked);
    assert!(without.refused.is_empty(), "no bit, no refused piece");
    assert_eq!(without.written.value, svc::ABSENT);
    // A walk that exhausted before any request went out: the bit's plane is handed the piece
    // (R-REJECTED, coordinator 2026-10-07, extends gap-2); a plane without the bit is sent nothing.
    let unsent = came(
        Gone {
            unsent: None,
            sends: false,
            then: exhausted(),
        },
        true,
    )
    .await;
    assert_eq!(
        unsent.refused,
        vec![code],
        "a walk that exhausted before any request went out is handed the refused piece"
    );
    assert_eq!(
        (unsent.written.value, unsent.written.bytes),
        (svc::FOUND, code.to_string().into_bytes()),
        "the refused piece's record write is written"
    );
    assert!(!unsent.leaked);
    let unsent_without = came(
        Gone {
            unsent: None,
            sends: false,
            then: exhausted(),
        },
        false,
    )
    .await;
    assert!(
        unsent_without.refused.is_empty(),
        "RED arm: a plane without the bit is handed nothing, sent or not"
    );
    assert_eq!(unsent_without.written.value, svc::ABSENT);
    assert_eq!(
        format!("{:?}", unsent.outcome),
        format!("{:?}", unsent_without.outcome),
        "the unit ends the same with the bit and without it"
    );
}

/// THE WALK THAT EXHAUSTED WITH NOTHING SENT NAMES WHY on its refused piece: for each way an
/// attempt leaves nothing on the wire (no member in hand, no route, an unbound need, a target that
/// is no path, a field name that is no token, an unrecordable dispatch, a failed auth call, a
/// refused open) the piece carries that `Unsent*` code in place of `breaker_open`, its record
/// write is written, the meter accrues nothing, and the unit ends, and its caller is answered,
/// byte for byte as the `breaker_open` exhaustion. RED: the piece named `breaker_open` whether
/// or not anything left, so a plane charged a hop that never left. A walk that says nothing left
/// is handed `breaker_open` as before (the arm below).
#[tokio::test]
async fn a_walk_that_exhausted_with_nothing_sent_names_why_on_its_refused_piece() {
    use busbar_contract::abi::plane::{nothing_sent, RefusalCode};
    use busbar_kernel::plane_driver::Pick;
    let exhausted = || Pick::Exhausted {
        status: 503,
        retry_after: Some(2),
        detail: "The service is temporarily overloaded. Please retry shortly.",
    };
    let gone = |unsent| Gone {
        unsent,
        sends: true,
        then: exhausted(),
    };
    let sent = came(gone(None), true).await;
    let breaker =
        busbar_contract::abi::plane::reason_code(busbar_contract::caps::ReasonCode::BreakerOpen);
    assert_eq!(
        sent.refused,
        vec![breaker],
        "a walk that sent names breaker_open"
    );
    assert!(!nothing_sent(breaker));
    let classes: Vec<RefusalCode> = RefusalCode::ALL
        .iter()
        .copied()
        .filter(|c| c.unsent())
        .collect();
    assert_eq!(classes.len(), 8, "one code per pre-byte class");
    for code in classes {
        let c = came(gone(Some(code)), true).await;
        assert_eq!(
            c.refused,
            vec![code.code()],
            "{code:?}: the piece names why"
        );
        assert!(nothing_sent(code.code()), "{code:?}");
        assert_eq!(
            (c.written.value, c.written.bytes),
            (svc::FOUND, code.code().to_string().into_bytes()),
            "{code:?}: the refused piece's record write is written"
        );
        assert_eq!(c.charged, 0, "{code:?}: nothing is charged");
        assert!(!c.leaked, "{code:?}");
        assert_eq!(
            format!("{:?}", c.outcome),
            format!("{:?}", sent.outcome),
            "{code:?}: the unit ends as the walk's exhaustion does"
        );
        assert_eq!(
            c.body, sent.body,
            "{code:?}: the caller's bytes are unchanged"
        );
    }
    assert_eq!(sent.charged, 0);
}

/// R-PUSH (spec :2603-2606, :3470): `next_tick_ns = 0` names no tick until the next wake of the
/// driver ticket, not "never": a plane whose `tick` answered `0` is ticked again after it wakes its
/// driver ticket. RED on the base: the schedule ended at the `0` answer.
#[tokio::test]
async fn a_wake_of_the_driver_ticket_re_polls_tick_after_an_answer_of_none() {
    let (plane, _book, driver) = driven(0);
    plane.wake.channel.store(true, Ordering::SeqCst);
    let waker = async {
        let ticks = || plane.ticks.lock().unwrap().len();
        while ticks() < 1 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(ticks(), 1, "no tick without a wake after an answer of 0");
        plane.wake.told.notify_one();
        while ticks() < 2 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        plane.wake.told.notify_one();
        while ticks() < 3 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            () = driver.ticks() => panic!("the schedule ended at the answer of 0 while a wake could come"),
            () = waker => {}
        }
    })
    .await
    .expect("each wake ticks once");
}

/// A plane that answers `0` and never wakes its driver ticket is ticked exactly once: the
/// behaviour of the planes that keep no push queue (R-PUSH changes nothing for them).
#[tokio::test]
async fn an_answer_of_none_with_no_wake_ticks_once_and_stays_quiet() {
    let (plane, _book, driver) = driven(0);
    plane.wake.channel.store(true, Ordering::SeqCst);
    let run = tokio::time::timeout(Duration::from_millis(150), driver.ticks()).await;
    assert!(
        run.is_err(),
        "the schedule waits on a wake that never comes"
    );
    assert_eq!(plane.ticks.lock().unwrap().len(), 1, "one tick, no more");
}

/// A wake re-arms the timer to the earlier of its deadline and the new answer: a wake whose tick
/// answers a nearer time is ticked at that time, not at the old deadline.
#[tokio::test]
async fn a_wake_re_arms_the_sleeping_timer_to_the_earlier_deadline() {
    let (plane, _book, driver) = driven(2_000_000_000);
    plane.wake.channel.store(true, Ordering::SeqCst);
    let waker = async {
        while plane.ticks.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // The next answer is 20 ms out; the old deadline (2 s) stands until the wake.
        plane.tick_every_ns.store(20_000_000, Ordering::SeqCst);
        plane.wake.told.notify_one();
        while plane.ticks.lock().unwrap().len() < 4 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::select! {
            () = driver.ticks() => panic!("the schedule ended"),
            () = waker => {}
        }
    })
    .await
    .expect("the wake brought the timer in from 2 s to 20 ms");
}

// ── a credential that cannot be presented ───────────────────────────────────────────────────────

/// What one failing secret leaves behind: the reference, and every string of it a caller must never
/// be handed (the variable, the path, the module, the reference as written).
struct Failing {
    secret: busbar_contract::secret_ref::SecretRef,
    markers: Vec<String>,
}

/// THE FAILING SECRETS this cell plants, one per source shape, each with its own markers: an unset
/// variable, a file that is not there, and a module no secret plugin answers.
fn failing_secrets() -> Vec<Failing> {
    use busbar_contract::secret_ref::SecretRef;
    let pid = std::process::id();
    let var = format!("BUSBAR_KERNEL_SECRET_MARKER_{pid}");
    std::env::remove_var(&var);
    let path = std::env::temp_dir()
        .join(format!("busbar-kernel-secret-marker-{pid}"))
        .display()
        .to_string();
    let _ = std::fs::remove_file(&path);
    let module = format!("secret-marker-module-{pid}");
    let opaque = format!("secret-marker-setting-{pid}");
    let plugin: SecretRef = serde_json::from_value(
        serde_json::json!({ "module": module, "settings": { "at": opaque } }),
    )
    .expect("a module reference");
    [
        (SecretRef::env(&var), vec![var.clone()]),
        (SecretRef::file(&path), vec![path.clone()]),
        (plugin, vec![module.clone()]),
    ]
    .into_iter()
    .map(|(secret, mut markers)| {
        markers.push(secret.describe());
        Failing { secret, markers }
    })
    .collect()
}

/// The markers `text` carries, without case.
fn markers_in(text: &str, failing: &Failing) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    failing
        .markers
        .iter()
        .filter(|m| lower.contains(&m.to_ascii_lowercase()))
        .cloned()
        .collect()
}

/// A FAR END WHOSE MEMBERS' CREDENTIALS CANNOT BE PRESENTED, the two ways production's far end meets
/// a secret that did not resolve: the member's one auth call is refused (its auth plugin holds no
/// credential), so nothing is sent; and the member's program is never spawned (the connector refuses
/// the open), so its attempt fails over before any byte reaches the plane. Each member's operator
/// text, naming the source, is held here, where the plugin and the connector hold theirs: nothing on
/// the far end's seam can carry it to the kernel.
struct Unpresentable {
    /// The refusal the secret source gave the operator.
    operator_text: String,
}

/// The member whose auth call is refused.
const UNBOUND: &str = "unbound";
/// The member whose program is never spawned.
const UNSPAWNED: &str = "unspawned";

impl busbar_kernel::plane_driver::FarEnd for Unpresentable {
    fn member<'a>(
        &'a self,
        _: &'a busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        attempt_no: u32,
    ) -> impl Future<Output = busbar_kernel::plane_driver::Pick> + Send + 'a {
        use busbar_kernel::plane_driver::Pick;
        let pick = match [UNBOUND, UNSPAWNED].get(attempt_no as usize - 1) {
            Some(m) => Pick::Member {
                name: (*m).to_string(),
                pool: "pool-a".to_string(),
                passthrough: false,
                provider: "acme".to_string(),
            },
            None => Pick::Exhausted {
                status: 503,
                retry_after: Some(2),
                detail: "The service is temporarily overloaded. Please retry shortly.",
            },
        };
        async move { pick }
    }

    async fn send(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        request: busbar_kernel::plane_driver::OutboundRequest,
    ) -> bool {
        request.member != UNBOUND
    }

    async fn next(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
    ) -> Option<busbar_kernel::plane_driver::FarPiece> {
        Some(busbar_kernel::plane_driver::FarPiece {
            last: true,
            fail_over: true,
            ..busbar_kernel::plane_driver::FarPiece::default()
        })
    }

    fn failure(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
    ) -> Option<&'static str> {
        Some("credential_unavailable")
    }

    async fn write(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        _: busbar_kernel::plane_driver::OutboundRequest,
    ) -> bool {
        false
    }
}

/// Run one unit through the one loop over any far end; its outcome.
async fn drive_over<F: busbar_kernel::plane_driver::FarEnd>(
    units: &busbar_kernel::plane_driver::PlaneUnits<'_, common::TestUnits, F, cases::Caller>,
) -> busbar_contract::caps::Outcome {
    use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        busbar_kernel::slice::ConcurrencyGauge::new(),
        busbar_contract::caps::Canary::new(),
        busbar_kernel::slice::LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = common::cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };
    match run_unit_async(&kernel, units, &common::ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}

/// A SECRET THAT DOES NOT RESOLVE REACHES THE CALLER AS A FIXED-CLASS REFUSAL NAMING NO SOURCE
/// (status row 127; the cell the retired tool-plane crate's `SetupRefusal::client_message` redaction
/// was until #511). For each failing source (an unset variable, a missing file, a module nothing
/// answers) the kernel's own resolver refuses with the operator's text, which names the source (the
/// control: the markers are there to be found). A unit whose every member's credential cannot be
/// presented (the auth call refused; the program never spawned) ends at the walk's terminal: the
/// plane's `refusal` is handed the one reason (`breaker_open`, class `Unreachable`) and the walk
/// terminal's own words (the exhausted pool's 1.5.5 sentence, a `&'static str` the far end's seam
/// carries: no operator text fits it), and the caller's render is byte-identical whichever source
/// failed and carries none of its markers. RED: a kernel that handed the plane any operator text
/// would fail the exact render, the byte-identity across sources, and the marker scan.
#[tokio::test]
async fn a_credential_that_cannot_be_presented_reaches_the_caller_as_a_fixed_class_refusal() {
    use busbar_contract::abi::plane::{class_of, RefusalClass};
    use busbar_contract::caps::{Outcome as UnitOutcome, ReasonCode, StepName};
    assert_eq!(class_of(ReasonCode::BreakerOpen), RefusalClass::Unreachable);
    let mut renders = Vec::new();
    for failing in failing_secrets() {
        let operator_text = busbar_kernel::config::secret::resolve_linked_string(&failing.secret)
            .expect_err("the reference does not resolve");
        assert!(
            !markers_in(&operator_text, &failing).is_empty(),
            "the control: the operator's text names the source: {operator_text}"
        );
        let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
        let (steps, far, caller) = (
            common::TestUnits::passing(),
            Unpresentable { operator_text },
            cases::Caller::default(),
        );
        assert!(!markers_in(&far.operator_text, &failing).is_empty());
        let units = r
            .driver
            .unit(&steps, &far, &caller, cases::arrival("/call", b"p"), 0);
        let outcome = drive_over(&units).await;
        assert!(
            matches!(
                outcome,
                UnitOutcome::Refused(StepName::Route, ReasonCode::BreakerOpen)
                    | UnitOutcome::Failed(StepName::Route, ReasonCode::BreakerOpen)
            ),
            "{}: {outcome:?}",
            failing.secret.describe()
        );
        let rendered = units.take_rendered().expect("the terminal is rendered");
        let render = format!(
            "{} {:?} {}",
            rendered.status,
            rendered.fields,
            String::from_utf8_lossy(&rendered.body)
        );
        assert_eq!(
            rendered.body,
            b"refused:503:The service is temporarily overloaded. Please retry shortly.:retry=2",
            "the plane is handed the fixed reason and the walk terminal's own words: {render}"
        );
        let found = markers_in(&render, &failing);
        assert!(
            found.is_empty(),
            "the caller was handed {found:?}: {render}"
        );
        assert_eq!(
            caller.text(),
            "",
            "nothing reached the caller but the refusal"
        );
        renders.push((rendered.status, rendered.fields, rendered.body));
    }
    renders.dedup();
    assert_eq!(
        renders.len(),
        1,
        "one fixed class: the caller cannot tell which source failed"
    );
}

// ── a unit cancelled before its first piece (audit P-M7) ────────────────────────────────────

/// A far end whose walk never picks a member: the unit waits in its route step with no piece
/// crossed until the driver cancels it.
struct Stalls;

impl busbar_kernel::plane_driver::FarEnd for Stalls {
    fn member<'a>(
        &'a self,
        _: &'a busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        _: u32,
    ) -> impl Future<Output = busbar_kernel::plane_driver::Pick> + Send + 'a {
        std::future::pending()
    }

    async fn send(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        _: busbar_kernel::plane_driver::OutboundRequest,
    ) -> bool {
        false
    }

    async fn next(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
    ) -> Option<busbar_kernel::plane_driver::FarPiece> {
        None
    }

    async fn write(
        &self,
        _: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
        _: busbar_kernel::plane_driver::OutboundRequest,
    ) -> bool {
        false
    }
}

/// A UNIT CANCELLED BEFORE ITS FIRST PIECE IS FREED (audit P-M7): a plane keys its units from
/// `arrive` (`ArriveIn::unit`), and the host's own `cancel` of a unit no piece ever reached names
/// that unit, so the plane finds and frees it. RED: the cancel carried the ticket alone, which the
/// plane learns only from a piece, so the unit stayed in its table forever (in a plane that did so, until
/// its 4096-unit cap answered every arrival 429).
#[tokio::test]
async fn a_unit_cancelled_before_its_first_piece_is_freed() {
    let r = Arc::new(rig(
        Way::Double,
        BufferCaps::default(),
        cases::Book::default(),
    ));
    let (steps, caller) = (common::TestUnits::passing(), cases::Caller::default());
    let units = r
        .driver
        .unit(&steps, &Stalls, &caller, cases::arrival("/call", b"x"), 0);
    let reloader = {
        let r = r.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            r.driver.reload();
        })
    };
    let outcome = drive_over(&units).await;
    reloader.await.unwrap();
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Failed(
                busbar_contract::caps::StepName::Route,
                busbar_contract::caps::ReasonCode::Drain
            )
        ),
        "{outcome:?}"
    );
    assert_eq!(r.stats()[stat::ON_PIECES], 0, "no piece crossed");
    assert_eq!(
        r.stats()[stat::CANCELS],
        1,
        "the driver's own cancel crossed"
    );
    assert!(
        r.plane.heads.lock().unwrap().is_empty(),
        "the cancel found the unit `arrive` keyed, and freed it"
    );
}

// ── the governed chain's caller reference ────────────────────────────────────────────────────────

/// A driver whose book lends caller references under `slot` (a governed chain), over the double.
fn governed(slot: busbar_kernel::plane_driver::CallerRefs) -> Rig {
    let plane = Arc::new(Double::default());
    let book = Arc::new(cases::Book::default());
    let driver = PlaneDriver::new(
        plane.clone(),
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses: cases::statuses(),
            caller_refs: Some(slot),
        },
        book.clone(),
        services(),
        ("test_plane", &serde_yaml::Value::Null),
    )
    .expect("the instance is admitted");
    Rig {
        plane,
        driver,
        book,
    }
}

/// One `/call` unit of the battery's verified principal through `r`: its outcome, and what the far
/// end was sent.
async fn verified_call(
    r: &Rig,
) -> (
    busbar_contract::caps::Outcome,
    Vec<busbar_kernel::plane_driver::OutboundRequest>,
) {
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"ping"), 0);
    let outcome = cases::drive(&units).await;
    (outcome, far.sent())
}

/// RED, THE GOVERNED CHAIN NEVER LENDS AN EMPTY CALLER REFERENCE: a plane reads an empty reference
/// as an ungoverned unit, so on a driver whose book lends references, a verified principal whose
/// reference cannot be derived (the book holds no key yet) is refused before the plane is lent the
/// unit: no piece crosses, nothing reaches the far end. Before the fix the unit ran, and every
/// piece was lent the empty reference.
#[tokio::test]
async fn red_a_governed_unit_with_no_caller_reference_is_refused_before_the_plane_runs() {
    let slot: busbar_kernel::plane_driver::CallerRefs = Arc::default();
    let r = governed(Arc::clone(&slot));
    let (outcome, sent) = verified_call(&r).await;
    assert!(
        matches!(
            outcome,
            busbar_contract::caps::Outcome::Refused(
                busbar_contract::caps::StepName::Verify,
                busbar_contract::caps::ReasonCode::Unauthenticated
            )
        ),
        "{outcome:?}"
    );
    assert_eq!(r.stats()[stat::ON_PIECES], 0, "no piece crossed");
    assert!(sent.is_empty(), "nothing reached the far end");
    assert!(
        r.plane.caller_refs.lock().unwrap().is_empty(),
        "no empty caller reference was lent"
    );
}

/// The same governed driver, once its book holds a key: the unit runs, and every piece is lent the
/// principal's own reference under that key (never empty, never the principal).
#[tokio::test]
async fn a_governed_unit_is_lent_its_principals_reference_once_the_book_holds_a_key() {
    let slot: busbar_kernel::plane_driver::CallerRefs = Arc::default();
    let r = governed(Arc::clone(&slot));
    let key = busbar_kernel::auth::CallerRefKey::derive(&[7u8; 32]);
    let expected = key.caller_ref(common::principal().as_str()).into_bytes();
    *slot.write().unwrap() = Some(Arc::new(key));
    let (outcome, sent) = verified_call(&r).await;
    assert!(
        matches!(outcome, busbar_contract::caps::Outcome::Completed),
        "{outcome:?}"
    );
    assert_eq!(sent.len(), 1, "the unit reached the far end");
    let lent = r.plane.caller_refs.lock().unwrap().clone();
    assert!(!lent.is_empty(), "the plane was lent the unit");
    assert!(
        lent.iter().all(|l| *l == expected),
        "every piece carries the principal's own reference: {lent:?}"
    );
}

/// An UNGOVERNED driver (no book: it lends no references) still runs a verified unit, every piece
/// lent the empty reference a plane reads as ungoverned.
#[tokio::test]
async fn an_ungoverned_unit_runs_lent_the_empty_reference() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (outcome, sent) = verified_call(&r).await;
    assert!(
        matches!(outcome, busbar_contract::caps::Outcome::Completed),
        "{outcome:?}"
    );
    assert_eq!(sent.len(), 1);
    let lent = r.plane.caller_refs.lock().unwrap().clone();
    assert!(
        !lent.is_empty() && lent.iter().all(Vec::is_empty),
        "{lent:?}"
    );
}
