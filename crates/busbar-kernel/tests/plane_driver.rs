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

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, ProjectIn, ProjectOut, RecordWrite,
    RefusalIn, RefusalOut, UnitCount, AUDIT_APPLIED, CANCEL_ABORTED, CANCEL_FAILED,
    CANCEL_OK_PARTIAL, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    PIECE_FIELDS, PIECE_HAS_STATUS, PIECE_LAST, PIECE_OUT_TEXT, PRINCIPAL_OPTIONAL, RECORD_AUDIT,
    RECORD_PUT, REFUSAL_ARRIVE, ROUTE_LOCAL, ROUTE_SESSION, UNITS_ESTIMATED, UNITS_REPORTED,
    VERDICT_RETRY,
};
use busbar_contract::abi::plane::{ServeIn, ServeOut};
use busbar_contract::caps::OpClassId;
use busbar_contract::plane::{TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::{
    Answered, Grow, InstanceDecl, Lent, PieceInFlight, PlaneCalls, ServeInFlight,
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
    pub(crate) fn stats(&self) -> [u64; stat::COUNT] {
        let mut out = [0; stat::COUNT];
        for (k, v) in out.iter_mut().enumerate() {
            *v = self.plane.stats[k].load(Ordering::SeqCst);
        }
        out
    }
}

pub(crate) fn rig(_way: Way, caps: BufferCaps, book: cases::Book) -> Rig {
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
}

/// One answer, held until it is due. The `out` carries plane pointers; the host reads it only
/// after the answer, on the task that awaits it.
struct Slot {
    answer: Option<(Answered, OnPieceOut)>,
    waker: Option<Waker>,
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
    /// The driver tickets minted, and every ticket recycled.
    drivers: Mutex<Vec<Ticket>>,
    recycled: Mutex<Vec<Ticket>>,
    /// Each `tick`'s `now_ns`, and the period the next one is asked for (`0` = none).
    ticks: Mutex<Vec<u64>>,
    tick_every_ns: AtomicU64,
    /// What it declares for its admission.
    declared: InstanceDecl,
    /// Its duplex sessions (a `/session` arrival states `ROUTE_SESSION`): see [`Sessions`].
    sessions: Arc<Sessions>,
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

/// The words the double's `/refuse-words` arrival states for its refusal.
const REFUSAL_WORDS: &[u8] = b"the body is not a document";

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

    /// The state of the unit `ticket` serves, removed.
    fn unit_of(&self, ticket: Ticket) -> Unit {
        let unit = self.tickets.lock().unwrap().remove(&ticket);
        unit.and_then(|k| self.units.lock().unwrap().remove(&k))
            .unwrap_or_default()
    }

    /// The disposition `cancel` answers for `u`; `None` = FAULT.
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
        if i.stream != 0 {
            return (self.session_piece(i, o), Hold::No);
        }
        let Some(head) = self.heads.lock().unwrap().get(&i.unit).cloned() else {
            // A piece of a unit that never arrived: the caller's head is not re-sent.
            return (ready(Outcome::Fault), Hold::No);
        };
        self.tickets.lock().unwrap().insert(t, i.unit);
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
                u.body.extend_from_slice(piece);
                if i.flags & PIECE_LAST == 0 {
                    return (ready(Outcome::Ready), Hold::No);
                }
                if head.as_slice() == b"/local" {
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
            u.saw_last |= i.flags & PIECE_LAST != 0;
            match u.mode.as_slice() {
                b"fault" => return (ready(Outcome::Fault), Hold::No),
                // The watchdog's FAULT for a crossing that has not returned: see `Hold::Wedge`.
                b"wedge" => return (ready(Outcome::Fault), Hold::Wedge),
                b"hang" | b"cancel-fault" => return (ready(Outcome::Pending), Hold::Forever),
                b"pend" if !u.pended => {
                    u.pended = true;
                    self.count(stat::HOST_CALLS);
                    hold = Hold::For(Duration::from_millis(30));
                }
                b"retry" => {
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
        }
        // A plane whose emitted messages are text (mode `text`): each whole message says so.
        if u.mode == b"text" && o.emitted > 0 && o.more == 0 {
            o.flags |= PIECE_OUT_TEXT;
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

/// How long a wedged crossing runs on after its FAULT answer.
pub(crate) const WEDGE: Duration = Duration::from_millis(300);

struct SendIn(OnPieceIn);
// SAFETY: the driver's `in`; its buffers are owned by the lent memory the wedge holds with it.
unsafe impl Send for SendIn {}

impl PlaneCalls for Double {
    fn now_ns(&self) -> u64 {
        now_ns()
    }

    // The hook stage is dormant in these driver proofs (no plane binds hooks): `project` is the
    // trait's required op, answered here as the no-projection pure op.
    fn project(
        &self,
        _input: &mut ProjectIn,
        _out: &mut ProjectOut,
        _grow: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome {
        Outcome::Ready
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

    fn refusal(
        &self,
        input: &mut RefusalIn,
        out: &mut RefusalOut,
        grow: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        // The reason crosses beside its text: a refusal whose code names another reason is FAULT
        // (the plane's own words for an arrival it refused are its text, not the kernel's).
        let named =
            busbar_contract::abi::plane::reason_of(input.reason).map(|r| r.as_str().as_bytes());
        if input.cause != REFUSAL_ARRIVE && named != Some(unsafe { text(input.text) }) {
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

    fn cancel(&self, ticket: Ticket) -> Option<u32> {
        self.count(stat::CANCELS);
        let u = self.unit_of(ticket);
        self.disposition(&u)
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
        let u = self.unit_of(ticket);
        let answer = match self.disposition(&u) {
            Some(d) => Answered {
                outcome: Outcome::Failed,
                short: false,
                disposition: Some(d),
            },
            None => ready(Outcome::Fault),
        };
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
        })));
        // SAFETY: the driver's `in`, whose buffers outlive the answer.
        let (answer, hold) = unsafe { self.piece(ticket, &input, &mut out) };
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
/// `0` ends the schedule (spec :3288, B.3.7).
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

/// A decision gate that refuses every request at 451 with its own words, counting its calls.
#[derive(Default)]
struct Refuses {
    calls: AtomicU32,
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
/// unit before anything reaches the far end; a refusal stops the unit at the gate's own status
/// and words (HookVeto), the binder is asked for the entry the plane's projection names, and
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
            busbar_contract::caps::Outcome::Failed(
                busbar_contract::caps::StepName::Route,
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
    assert_eq!(*binder.asked.lock().unwrap(), vec![String::new()]);
    assert!(far.sent().is_empty(), "nothing reached the far end");
    let rendered = units.take_rendered().expect("the veto is rendered");
    assert_eq!(rendered.status, 451);
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
