// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(unsafe_code, clippy::missing_safety_doc)]

mod common;

#[path = "support/plane_driver_cases.rs"]
mod cases;

#[path = "support/plane_driver_hook_cases.rs"]
mod hook_cases;

#[path = "support/plane_driver_close_cases.rs"]
mod close_cases;

#[path = "support/plane_driver_session_input_cases.rs"]
mod session_input_cases;

#[path = "support/plane_driver_retirement_cases.rs"]
mod retirement_cases;

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

struct Slot {
    answer: Option<(Answered, OnPieceOut)>,
    waker: Option<Waker>,
    polled_pending: bool,

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
                s.polled_pending = true;
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
    held_lent: Mutex<HashMap<Ticket, Lent>>,
    cancelled_units: Mutex<HashMap<u64, Option<u32>>>,
    controlled: Mutex<Option<(Arc<Shared>, Answered, OnPieceOut)>>,
    pending_notice: Mutex<Option<std::sync::mpsc::Sender<bool>>>,
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
    initials: AtomicU64,
    server_first: AtomicBool,
    read: Mutex<Vec<(u64, Vec<u8>)>>,
    read_at: Mutex<Vec<usize>>,
    collects: AtomicU64,
    named: Mutex<Vec<u64>>,
    told: tokio::sync::Notify,
    input_mode: Mutex<SessionInputMode>,
    far_pending: AtomicBool,
    cancel_row: AtomicBool,
    delay_cancel_reply: AtomicBool,
    cancel_reply: Arc<tokio::sync::Notify>,
    /// A controlled crossing that still borrows the session input after its answer or drop.
    borrowed: Mutex<Option<(SendIn, Lent)>>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum SessionInputMode {
    #[default]
    Ready,
    Pending,
    /// A worker-owned Pending op that cancellation can retire with its siblings.
    Cancellable,
    Fault,
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

const NOT_FOR_THE_CALLER: &[u8] = b"not-for-the-caller";

const REFUSAL_WORDS: &[u8] = b"the body is not a document";

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
    fn release_controlled(&self, require_pending_poll: bool) -> bool {
        let (slot, answer, out) = {
            let mut held = self.controlled.lock().unwrap();
            let Some((slot, _, _)) = held.as_ref() else {
                return false;
            };
            if require_pending_poll && !slot.0.lock().unwrap().polled_pending {
                return false;
            }
            held.take().unwrap()
        };
        self.count(stat::HOST_CALLS);
        slot.put(answer, out);
        true
    }

    fn count(&self, k: usize) {
        self.stats[k].fetch_add(1, Ordering::SeqCst);
    }

    fn closed(&self, unit: u64) {
        *self.closes.lock().unwrap().entry(unit).or_default() += 1;
    }

    fn unit_of(&self, ticket: Ticket) -> Unit {
        let unit = self.tickets.lock().unwrap().remove(&ticket);
        unit.and_then(|k| self.units.lock().unwrap().remove(&k))
            .unwrap_or_default()
    }

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

    fn cancel_group(
        &self,
        ticket: Ticket,
        unit: u64,
        explicit: bool,
    ) -> Option<busbar_contract::plane_calls::Cancelled> {
        let tickets = self
            .tickets
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(ticket, key)| (*key == unit).then_some(*ticket))
            .collect::<Vec<_>>();
        let previous = self.cancelled_units.lock().unwrap().get(&unit).copied();
        let mut cancelled = match previous {
            Some(disposition) => {
                disposition.map(|disposition| busbar_contract::plane_calls::Cancelled {
                    disposition,
                    writes: Vec::new(),
                })
            }
            None => {
                self.count(stat::CANCELS_ON_WORKER);
                let mut cancelled = self.cancel(ticket, unit);
                if self.sessions.cancel_row.load(Ordering::SeqCst) {
                    if let Some(cancelled) = cancelled.as_mut() {
                        cancelled
                            .writes
                            .push(busbar_contract::plane_calls::CancelWrite {
                                kind: AUDIT_APPLIED,
                                op: RECORD_AUDIT,
                                key: b"session.cancel".to_vec(),
                                value: b"session:7".to_vec(),
                            });
                    }
                }
                self.sessions
                    .open
                    .lock()
                    .unwrap()
                    .retain(|stream| *stream != unit);
                self.cancelled_units
                    .lock()
                    .unwrap()
                    .insert(unit, cancelled.as_ref().map(|c| c.disposition));
                cancelled
            }
        };
        let mut held = Vec::new();
        {
            let mut table = self.held.lock().unwrap();
            for sibling in &tickets {
                if let Some((slot, out)) = table.remove(sibling) {
                    held.push((*sibling, slot, out));
                }
            }
        }
        for (sibling, slot, out) in held {
            if !explicit && sibling == ticket {
                if let Some(cancelled) = cancelled.as_mut() {
                    slot.0.lock().unwrap().writes = std::mem::take(&mut cancelled.writes);
                }
            }
            slot.put(
                match cancelled.as_ref() {
                    Some(cancelled) => Answered {
                        outcome: Outcome::Failed,
                        short: false,
                        disposition: Some(cancelled.disposition),
                    },
                    None => ready(Outcome::Fault),
                },
                out,
            );
            let lent = self.held_lent.lock().unwrap().remove(&sibling);
            drop(lent);
        }

        if *self.sessions.input_mode.lock().unwrap() == SessionInputMode::Cancellable {
            let mut borrowed = self.sessions.borrowed.lock().unwrap();
            if borrowed
                .as_ref()
                .is_some_and(|(input, _)| input.0.unit == unit)
            {
                borrowed.take();
            }
        }
        cancelled
    }

    unsafe fn piece(&self, t: Ticket, i: &OnPieceIn, o: &mut OnPieceOut) -> (Answered, Hold) {
        self.count(stat::ON_PIECES);
        self.stats[stat::UNIT].store(i.unit, Ordering::SeqCst);
        self.caller_refs
            .lock()
            .unwrap()
            .push(text(i.caller_ref).to_vec());
        if i.stream != 0 {
            let answer = self.session_piece(i, o);
            let mode = *self.sessions.input_mode.lock().unwrap();
            if (i.from == FROM_CALLER && i.bytes.len != 0 && mode == SessionInputMode::Cancellable)
                || (i.from == FROM_FAR_END && self.sessions.far_pending.load(Ordering::SeqCst))
            {
                return (ready(Outcome::Failed), Hold::Forever);
            }
            return match (i.from == FROM_CALLER && i.bytes.len != 0, mode) {
                (true, SessionInputMode::Pending) => (answer, Hold::Forever),
                (true, SessionInputMode::Fault) => (ready(Outcome::Fault), Hold::No),
                _ => (answer, Hold::No),
            };
        }
        let Some(head) = self.heads.lock().unwrap().get(&i.unit).cloned() else {
            return (ready(Outcome::Fault), Hold::No);
        };
        self.tickets.lock().unwrap().insert(t, i.unit);
        if i.from == FROM_KERNEL && i.flags & PIECE_REFUSED != 0 {
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
                    o.reply_status = 200;
                    let n = u.body.len().min(i.reply_cap);
                    std::ptr::copy_nonoverlapping(u.body.as_ptr(), i.reply_buf, n);
                    o.emitted = n as u64;
                    o.flags = EMIT_DONE;
                    return (ready(Outcome::Ready), Hold::No);
                }
                if head.as_slice() == b"/audit" {
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

            if i.flags & PIECE_HAS_STATUS != 0 && i.flags & PIECE_FIELDS == 0 {
                u.final_answer = i.flags & PIECE_FINAL != 0;
            }
            u.saw_last |= i.flags & PIECE_LAST != 0;
            match u.mode.as_slice() {
                b"fault" => return (ready(Outcome::Fault), Hold::No),

                b"wedge" => return (ready(Outcome::Fault), Hold::Wedge),
                b"hang" | b"hang-row" | b"cancel-fault" => {
                    return (ready(Outcome::Pending), Hold::Forever)
                }
                b"pend" if !u.pended => {
                    u.pended = true;
                    self.count(stat::HOST_CALLS);
                    hold = Hold::For(Duration::from_millis(30));
                }
                b"pend-controlled" if !u.pended => {
                    u.pended = true;
                    hold = Hold::Forever;
                }

                b"done-late" | b"retry-done-late" if u.far_pieces == 2 => {
                    hold = Hold::For(DONE_LATE);
                }
                b"retry" => {
                    o.verdict = VERDICT_RETRY;
                    return (ready(Outcome::Ready), Hold::No);
                }

                b"done-retry" => {
                    o.flags = EMIT_DONE;
                    o.verdict = VERDICT_RETRY;
                    return (ready(Outcome::Ready), Hold::No);
                }
                b"short" | b"short-twice" if u.short => {
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

            o.tap_fault = match u.mode.as_slice() {
                b"tap-bad-json" => busbar_contract::abi::plane::TAP_FAULT_BAD_JSON,
                b"tap-unknown" => 0xC8,
                _ => busbar_contract::abi::plane::TAP_FAULT_NONE,
            };
        }

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

            if u.mode == b"retry-done-late" {
                o.verdict = VERDICT_RETRY;
            }
        }

        if u.mode == b"text" && o.emitted > 0 && o.more == 0 {
            o.flags |= PIECE_OUT_TEXT;
        }

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
                let initial = {
                    let mut open = s.open.lock().unwrap();
                    let initial = !open.contains(&i.stream);
                    if initial {
                        open.push(i.stream);
                    }
                    initial
                };
                if initial && body.is_empty() {
                    s.initials.fetch_add(1, Ordering::SeqCst);
                    if s.server_first.load(Ordering::SeqCst) {
                        let mut at = 0;
                        o.verb = put(i, &mut at, b"GET");
                        o.target = put(i, &mut at, b"/open");
                        o.arena_written = at as u64;
                        o.flags = EMIT_TO_FAR_END;
                    }
                    return ready(Outcome::Ready);
                }
                s.read_at.lock().unwrap().push(i.bytes.ptr as usize);
                s.read.lock().unwrap().push((i.stream, body.clone()));
                if s.server_first.load(Ordering::SeqCst) {
                    reply(o, &body);
                    o.flags = EMIT_TO_FAR_END;
                    return ready(Outcome::Ready);
                }
                o.reply_status = 200;
                reply(o, &[b"open:".as_slice(), &body].concat());
            }
            FROM_KERNEL if i.attempt_no == 0 => {
                s.collects.fetch_add(1, Ordering::SeqCst);
                reply(o, b"keepalive;");
            }
            FROM_KERNEL if s.server_first.load(Ordering::SeqCst) => {}
            FROM_FAR_END if s.server_first.load(Ordering::SeqCst) => {
                o.reply_status = 200;
                reply(o, bytes(i.bytes));
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

    Wedge,
}

pub(crate) const DONE_LATE: Duration = Duration::from_millis(120);

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
                b"/post-only" if unsafe { text(input.method) } != b"POST" => {
                    out.refusal = 9;
                    out.refusal_status = 405;
                    return Outcome::Refused;
                }
                b"/refuse" => {
                    out.refusal = 7;
                    out.refusal_status = 404;
                    return Outcome::Refused;
                }
                b"/refuse-words" => {
                    out.refusal = 7;
                    out.refusal_status = 400;
                    out.head.error = AbiStr::over(REFUSAL_WORDS);
                    return Outcome::Refused;
                }
                b"/refuse-entry" | b"/refuse-entry-after" => {
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
                    out.route = ROUTE_SCOPE_LOCAL;
                    vec![estimate(0)]
                }
                b"/session" => {
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

        let target = unsafe { text(input.target) };
        if target == b"/target-echo" {
            body.extend_from_slice(b" for ");
            body.extend_from_slice(target);
        }

        if input.retry_after_s != 0 {
            body.extend_from_slice(format!(":retry={}", input.retry_after_s).as_bytes());
        }
        if input.plane_code != 0 {
            body.extend_from_slice(format!(":{}@{}", input.plane_code, input.unit).as_bytes());
        }

        if input.trust != 0 {
            body.extend_from_slice(format!(":trust={}", input.trust).as_bytes());
        }

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
            out.head.outcome = RawOutcome::of(Outcome::Fault);
            out.view.flags = busbar_contract::abi::plane::PROJECT_FAULT_UNPARSEABLE;
            return Outcome::Fault;
        }
        match target.as_slice() {
            b"/fault-unmarked" => {
                out.head.outcome = RawOutcome::of(Outcome::Fault);
                return Outcome::Fault;
            }

            b"/panics" => {
                out.head.outcome = RawOutcome::of(Outcome::Fault);
                return Outcome::Fault;
            }

            b"/no-crossing" => return Outcome::Fault,

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
        let not_applicable = target == b"/rewrite-not-applicable" && !rewrite.is_empty();
        let rewritten = (!rewrite.is_empty() && target != b"/no-rewrite" && !not_applicable)
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
                flags: if not_applicable {
                    busbar_contract::abi::plane::PROJECT_REWRITE_NOT_APPLICABLE
                } else {
                    0
                },
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

    fn bind_unit(&self, ticket: Ticket, unit: u64) {
        self.tickets.lock().unwrap().insert(ticket, unit);
    }

    fn cancel_unit(
        &self,
        ticket: Ticket,
        unit: u64,
    ) -> Pin<Box<dyn Future<Output = Option<busbar_contract::plane_calls::Cancelled>> + Send>> {
        let cancelled = self.cancel_group(ticket, unit, true);
        let delayed = self.sessions.delay_cancel_reply.load(Ordering::SeqCst);
        let reply = self.sessions.cancel_reply.clone();
        Box::pin(async move {
            if delayed {
                reply.notified().await;
            }
            cancelled
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

    fn drop_client(&self, ticket: Ticket) {
        if !self.held.lock().unwrap().contains_key(&ticket) {
            return;
        }
        let Some(unit) = self.tickets.lock().unwrap().get(&ticket).copied() else {
            return;
        };
        let _ = self.cancel_group(ticket, unit, false);
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
            polled_pending: false,
            writes: Vec::new(),
        })));
        // SAFETY: the driver's `in`, whose buffers outlive the answer.
        let (answer, hold) = unsafe { self.piece(ticket, &input, &mut out) };
        if input.stream != 0
            && input.from == FROM_CALLER
            && input.bytes.len != 0
            && *self.sessions.input_mode.lock().unwrap() != SessionInputMode::Ready
        {
            let previous = self
                .sessions
                .borrowed
                .lock()
                .unwrap()
                .replace((SendIn(input), lent.clone()));
            assert!(previous.is_none(), "only one controlled session crossing");
        }

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
                if answer.outcome == Outcome::Ready {
                    *self.controlled.lock().unwrap() = Some((slot.clone(), answer, out));
                    if let Some(notice) = self.pending_notice.lock().unwrap().as_ref() {
                        let _ = notice.send(true);
                    }
                } else {
                    self.held_lent.lock().unwrap().insert(ticket, lent.clone());
                    self.held
                        .lock()
                        .unwrap()
                        .insert(ticket, (slot.clone(), out));
                }
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

struct PendingWatchdog {
    stop: std::sync::mpsc::Sender<bool>,
    thread: Option<std::thread::JoinHandle<bool>>,
}

impl PendingWatchdog {
    fn finish(&mut self) -> bool {
        let _ = self.stop.send(false);
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("cleanup watchdog")
    }
}

impl Drop for PendingWatchdog {
    fn drop(&mut self) {
        let _ = self.stop.send(false);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn a_pending_piece_is_released_by_another_task_on_the_same_runtime() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
        let (notice, entered) = std::sync::mpsc::channel();
        *r.plane.pending_notice.lock().unwrap() = Some(notice.clone());
        let cleanup_plane = Arc::clone(&r.plane);
        let mut watchdog = PendingWatchdog {
            stop: notice,
            thread: Some(std::thread::spawn(move || {
                if entered.recv() != Ok(true) {
                    return false;
                }
                if matches!(
                    entered.recv_timeout(Duration::from_secs(5)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    return cleanup_plane.release_controlled(false);
                }
                false
            })),
        };
        let released = Arc::new(AtomicBool::new(false));
        let observer = {
            let plane = Arc::clone(&r.plane);
            let released = Arc::clone(&released);
            tokio::spawn(async move {
                loop {
                    if plane.release_controlled(true) {
                        released.store(true, Ordering::SeqCst);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
        };
        let (steps, far, caller) = (
            common::TestUnits::passing(),
            cases::Far::new(&["pend-controlled"], cases::CHUNKS),
            cases::Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
        let outcome = cases::drive(&units).await;
        observer.abort();
        let _ = observer.await;
        let forced = watchdog.finish();
        drop(units);
        r.driver.sweep();
        assert!(
            !forced,
            "the runtime needed external cleanup to resume its pending piece"
        );
        assert!(
            released.load(Ordering::SeqCst),
            "the sibling ran during the actual pending poll"
        );
        assert_eq!(outcome, busbar_contract::caps::Outcome::Completed);
        assert_eq!(caller.text(), "hello far end");
        assert_eq!(
            r.stats()[stat::HOST_CALLS],
            1,
            "the one release woke the piece"
        );
    });
}

use busbar_contract::abi::host::service as svc;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_contract::records::RecordStore;
use busbar_contract::services::{Caller as Instance, HostServices, Ran, RecordsList, Stored};
use busbar_kernel::host_records::RecordRows;
use busbar_kernel::host_services::{InstanceFacts, KernelServices, Offload};
use busbar_plugin_loader::store_v3::LoadedStore;

fn actual_store() -> Arc<LoadedStore> {
    use busbar_plugin_loader::dispatch::kinds::store::Store;
    use busbar_plugin_loader::dispatch::{
        load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let stated = rendering_of_library(&path)
        .expect("read the actual Store statement")
        .expect("Store exports its statement");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<Store>(
        &path,
        &stated,
        Bind {
            instance: format!("plane-records-{}", busbar_kernel::door::op_id().counter()).into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("load the actual Store through its ABI");
    let settings =
        std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into());
    Arc::new(
        LoadedStore::open(
            plugin,
            dispatcher,
            settings.as_bytes(),
            busbar_kernel::door::op_id,
        )
        .expect("open the actual Store"),
    )
}

struct Rows(Arc<LoadedStore>);

impl RecordRows for Rows {
    fn claim(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<bool, busbar_contract::kinds::StoreError> {
        busbar_contract::records::RecordStore::redeem_plane_token(
            &*self.0, kind, token, expires_at, now,
        )
        .map_err(|e| busbar_contract::kinds::StoreError::Rejected(e.0))
    }
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

fn records() -> Arc<KernelServices> {
    let store = actual_store();
    let s = KernelServices::new()
        .with_records(Arc::new(Rows(Arc::clone(&store))))
        .with_pool(Arc::new(Inline));
    let facts = InstanceFacts {
        record_kinds: vec![RecordSchemaId::new("task")],
        ..InstanceFacts::default()
    };
    s.admit("inst", facts).unwrap();
    Arc::new(s)
}

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
    std::mem::take(&mut answer(|l| s.records_list(&instance(), all, l)).bytes)
}

async fn write(driver: &PlaneDriver, body: &[u8]) -> busbar_contract::caps::Outcome {
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&[], &[]),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/records", body), 0);
    cases::drive(&units).await
}

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

fn declaring() -> Double {
    Double {
        declared: InstanceDecl {
            conditional_records: false,
            conditional_record_kinds: Vec::new(),
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

fn stored() -> Arc<KernelServices> {
    let store = actual_store();
    Arc::new(
        KernelServices::new()
            .with_records(Arc::new(Rows(store)))
            .with_pool(Arc::new(Inline)),
    )
}

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

#[tokio::test]
async fn an_uncalled_upstream_is_never_fetched_over_time() {
    let services = stored();
    let section: serde_yaml::Value = serde_yaml::from_str("peer: {reverify: 1h}").unwrap();
    let (_plane, _book, driver) = driven_over(declaring(), 0, services.clone(), &section);
    let due = |s: &KernelServices| std::mem::take(&mut s.trust_due(&instance()).bytes);
    assert!(due(&services).is_empty(), "nothing is due before a tick");
    tokio::time::timeout(Duration::from_secs(5), driver.ticks())
        .await
        .expect("one tick");
    assert!(
        due(&services).is_empty(),
        "an upstream nobody called is not due after the tick"
    );
}

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

fn untrusted(outcome: &busbar_contract::caps::Outcome) -> bool {
    matches!(
        outcome,
        busbar_contract::caps::Outcome::Refused(
            busbar_contract::caps::StepName::Approve,
            busbar_contract::caps::ReasonCode::Untrusted
        )
    )
}

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

    let (outcome, _) = approved(&driver, "/call").await;
    assert!(!untrusted(&outcome), "{outcome:?}");

    let (outcome, body) = approved(&driver, "/trusted/stranger").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(1));
    let (outcome, body) = approved(&driver, "/trusted/peer").await;
    assert!(untrusted(&outcome), "{outcome:?}");
    assert_eq!(body, refused(2));

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

    assert_eq!(
        services.trust_rule("inst/stranger", Ruling::Approve),
        Err(busbar_kernel::host_services::TrustRefused::NoSuchKey)
    );
}

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

#[test]
fn a_planes_work_section_overrides_the_hosts_work_bounds() {
    use busbar_kernel::host_units::UnitRecord;
    use busbar_kernel::host_work::{refusal, WorkBounds};
    let store = actual_store();
    let host = WorkBounds {
        max_live: 3,
        retain_ms: 300_000,
    };
    let services = Arc::new(
        KernelServices::new()
            .with_records(Arc::new(Rows(store)))
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

#[path = "support/plane_driver_write_behind.rs"]
mod write_behind;

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

fn spent_caller() -> common::TestUnits {
    common::TestUnits {
        refuse_at: Some((
            busbar_contract::caps::StepName::Admit,
            busbar_contract::caps::ReasonCode::RateLimited,
        )),
        ..common::TestUnits::passing()
    }
}

fn the_planes_refusal(rendered: &busbar_kernel::plane_driver::Rendered) -> bool {
    let body = String::from_utf8_lossy(&rendered.body);
    rendered.status == ENTRY_REFUSED_STATUS && body.contains(&format!(":{ENTRY_REFUSED}@"))
}

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

    let gov = Arc::new(GovState::new(actual_store(), None).expect("gov"));
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

    money.settle_end(unit, rendered.status);
    let usage = spend();
    assert_eq!(
        (usage.spend_cents, usage.tokens),
        (0, 0),
        "nothing net-charged, nothing ledgered"
    );
}

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
        busbar_kernel::canary::Canary::new(),
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
        taps: None,
    };
    let ctx = common::ctx(7);
    let unit = run_unit_async(&kernel, &units, &ctx, run, &units);

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
            reads: Arc::new(|_: &str, _: Option<&str>, _: &str, _: bool| {}),
        })
    }
}

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

    assert_eq!(*binder.asked.lock().unwrap(), vec![String::new()]);
    assert!(far.sent().is_empty(), "nothing reached the far end");
    let rendered = units.take_rendered().expect("the veto is rendered");
    assert_eq!(rendered.status, 451);
}

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

async fn drive_gone(
    units: &busbar_kernel::plane_driver::PlaneUnits<'_, common::TestUnits, Gone, cases::Caller>,
) -> (busbar_contract::caps::Outcome, u64) {
    use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
    use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        busbar_kernel::canary::Canary::new(),
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
        taps: None,
    };
    let outcome = match run_unit_async(&kernel, units, &common::ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    };
    (outcome, meter.total())
}

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
            let expected_written = code.to_string().into_bytes();
            assert_eq!(
                (c.written.value, c.written.bytes.as_slice()),
                (svc::FOUND, expected_written.as_slice()),
                "the refused piece's record write is written"
            );
        } else {
            assert!(c.refused.is_empty(), "no refused piece");
            assert_eq!(c.written.value, svc::ABSENT, "nothing written");
        }
    }
}

#[tokio::test]
async fn a_walk_that_ends_after_a_request_went_out_is_handed_as_a_piece_first() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::plane_driver::Pick;
    let code = busbar_contract::abi::plane::reason_code(ReasonCode::BreakerOpen);
    let expected_written = code.to_string().into_bytes();
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
        (taken.written.value, taken.written.bytes.as_slice()),
        (svc::FOUND, expected_written.as_slice()),
        "the refused piece's record write is written"
    );
    assert!(!taken.leaked && !without.leaked);
    assert!(without.refused.is_empty(), "no bit, no refused piece");
    assert_eq!(without.written.value, svc::ABSENT);

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
        (unsent.written.value, unsent.written.bytes.as_slice()),
        (svc::FOUND, expected_written.as_slice()),
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
        let expected_written = code.code().to_string().into_bytes();
        assert_eq!(
            (c.written.value, c.written.bytes.as_slice()),
            (svc::FOUND, expected_written.as_slice()),
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

#[tokio::test]
async fn a_wake_re_arms_the_sleeping_timer_to_the_earlier_deadline() {
    let (plane, _book, driver) = driven(2_000_000_000);
    plane.wake.channel.store(true, Ordering::SeqCst);
    let waker = async {
        while plane.ticks.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

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

struct Failing {
    secret: busbar_contract::secret_ref::SecretRef,
    markers: Vec<String>,
}

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

fn markers_in(text: &str, failing: &Failing) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    failing
        .markers
        .iter()
        .filter(|m| lower.contains(&m.to_ascii_lowercase()))
        .cloned()
        .collect()
}

struct Unpresentable {
    operator_text: String,
}

const UNBOUND: &str = "unbound";

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

async fn drive_over<F: busbar_kernel::plane_driver::FarEnd>(
    units: &busbar_kernel::plane_driver::PlaneUnits<'_, common::TestUnits, F, cases::Caller>,
) -> busbar_contract::caps::Outcome {
    use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        busbar_kernel::slice::ConcurrencyGauge::new(),
        busbar_kernel::canary::Canary::new(),
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
        taps: None,
    };
    match run_unit_async(&kernel, units, &common::ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}

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
