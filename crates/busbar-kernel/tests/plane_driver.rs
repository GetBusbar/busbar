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

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, RefusalIn, RefusalOut, Span, UnitCount,
    CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_OPTIONAL, UNITS_ESTIMATED,
    UNITS_REPORTED, VERDICT_RETRY,
};
use busbar_contract::caps::OpClassId;
use busbar_contract::plane_calls::{Answered, Grow, Lent, PieceInFlight, PlaneCalls};
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
        },
        book.clone(),
    );
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
            u.pending.extend_from_slice(piece);
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
        (ready(Outcome::Ready), hold)
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
                b"/refuse" => return Outcome::Refused,
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

    fn refusal(
        &self,
        input: &mut RefusalIn,
        out: &mut RefusalOut,
        grow: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        let body = [
            b"refused:".as_slice(),
            input.status.to_string().as_bytes(),
            b":",
            unsafe { text(input.text) },
        ]
        .concat();
        let (name, value) = (b"content-type".as_slice(), b"text/plain".as_slice());
        let arena = name.len() + value.len();
        for call in 0..2 {
            if body.len() > input.reply_cap || input.fields_cap < 1 || arena > input.arena_cap {
                if call == 1 {
                    return Outcome::Fault;
                }
                out.reply_needed = body.len() as u64;
                out.fields_needed = 1;
                out.arena_needed = arena as u64;
                grow(out, input);
                continue;
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

    fn recycle(&self, _ticket: Ticket) {}

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
}

struct SendOut(OnPieceOut);
// SAFETY: plain data the double wrote; its pointers are never dereferenced.
unsafe impl Send for SendOut {}
