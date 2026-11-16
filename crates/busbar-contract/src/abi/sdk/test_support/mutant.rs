// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MUTANT ROW (SDK-SAFE-TEST-HOST §3.4): a real door with one fact changed, for a negative
//! load case. It answers a [`RawDoorFn`] (never a `DoorFn`, which cannot be NULL), and the test
//! hands it only to the host's `Image::mutant`, so the raw door never reaches test code.
//!
//! Every fact a row changes is a scalar or a `&'static str` the row itself lays out: no row takes
//! a pointer, a list or a struct from test code, so every pointer in a mutant is still the real
//! door's `'static` data.

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use crate::abi::mechanism::call::{AbiStr, Op, OutHead, Outcome, RawOutcome};
use crate::abi::mechanism::door::{Door, DoorFn, DoorParts, KindTailHead, Statement};
use crate::abi::mechanism::lifecycle::OpsHead;
use crate::abi::mechanism::KindCode;
use crate::abi::plane::PlaneTail;
use crate::abi::sdk::door::RawDoorFn;
use crate::abi::transport::{
    slot as framer, AdoptIn, BeginIn, DatagramLane, DatagramRoute, EmitIn, EncodeIn, FinishIn,
    FramerOut, FramerSink, FramingIn, IngestIn, Ops as TransportOps, RefuseIn, TransportTail,
    LANE_CLEAR,
};

/// How many mutants one process may forge: the bank of door functions below.
const BANK: usize = 16;

static NEXT: AtomicUsize = AtomicUsize::new(0);

static DOORS: [AtomicPtr<Door>; BANK] = [const { AtomicPtr::new(std::ptr::null_mut()) }; BANK];

/// The text each slot's failing READY answers: a `&'static str`'s pointer and length.
static READY_TEXT: [(AtomicPtr<u8>, AtomicUsize); BANK] =
    [const { (AtomicPtr::new(std::ptr::null_mut()), AtomicUsize::new(0)) }; BANK];

/// READY crossings into a failing READY, process-wide.
static READY_CALLS: AtomicU64 = AtomicU64::new(0);

/// The framer op a corrupting bank slot wraps, which of the door's slots it sat in, and which of
/// its wire-writing answers is corrupted.
#[derive(Debug, Clone, Copy)]
struct Corrupting {
    real: Op,
    slot: u32,
    nth: u64,
}

/// Each bank slot's corrupting wrap, set once when its mutant is forged.
static CORRUPTING: [OnceLock<Corrupting>; BANK] = [const { OnceLock::new() }; BANK];

/// Each bank slot's READY answers that wrote wire bytes so far.
static WIRED: [AtomicU64; BANK] = [const { AtomicU64::new(0) }; BANK];

/// The framer slots whose `in` lends a datagram lane (DETACH and TIMER share `FramingIn`), in the
/// order of a dropping bank slot's ops.
const LANE_OPS: [u32; 6] = [
    framer::BEGIN,
    framer::INGEST,
    framer::EMIT,
    framer::FINISH,
    framer::DETACH,
    framer::TIMER,
];

/// A dropping bank slot's wrap: the op each slot of [`LANE_OPS`] held (`None`: unserved, and left
/// so), and every how many media routes one is dropped.
#[derive(Debug, Clone, Copy)]
struct Dropping {
    real: [Option<Op>; LANE_OPS.len()],
    every: u64,
}

/// Each bank slot's dropping wrap, set once when its mutant is forged.
static DROPPING: [OnceLock<Dropping>; BANK] = [const { OnceLock::new() }; BANK];

/// Each bank slot's media routes seen so far, across answers.
static MEDIA: [AtomicU64; BANK] = [const { AtomicU64::new(0) }; BANK];

/// Media routes dropped by any dropping mutant, process-wide.
static DROPPED_MEDIA: AtomicU64 = AtomicU64::new(0);

/// One dropping op per bank slot for the lane op at index `$k` of [`LANE_OPS`].
macro_rules! drop_row {
    ($k:literal; $($i:literal)+) => {
        [$({
            extern "C" fn dropping(
                instance: *mut c_void,
                input: *const c_void,
                out: *mut c_void,
            ) -> RawOutcome {
                drop_media($i, $k, instance, input, out)
            }
            dropping
        }),+]
    };
}

macro_rules! bank {
    ($($i:literal)+) => {
        /// One door function per slot: each answers the door its slot holds (NULL until forged, or
        /// for a `null()` mutant). A load cannot panic, so nothing unwinds out of `extern "C"`.
        const FNS: [RawDoorFn; BANK] = [$({
            extern "C" fn slot() -> *const Door {
                DOORS[$i].load(Ordering::Acquire)
            }
            slot
        }),+];
        /// One failing READY per slot: it answers FAILED with its slot's text. Atomics and two
        /// plain stores only, so it cannot panic or unwind out of `extern "C"`.
        const READY: [crate::abi::mechanism::call::Op; BANK] = [$({
            extern "C" fn ready(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
                fail_ready($i, out)
            }
            ready
        }),+];
        /// One corrupting framer op per slot: it forwards the crossing to the op it wraps, then
        /// corrupts the answer's wire. Atomics, a `OnceLock` read and one byte store besides the
        /// wrapped op (an SDK op, which catches its own panics), so nothing unwinds out of
        /// `extern "C"`.
        const CORRUPT: [Op; BANK] = [$({
            extern "C" fn corrupt(
                instance: *mut c_void,
                input: *const c_void,
                out: *mut c_void,
            ) -> RawOutcome {
                corrupt_wire($i, instance, input, out)
            }
            corrupt
        }),+];
        /// The dropping ops: per lane op of [`LANE_OPS`], one per slot. Each forwards the
        /// crossing to the op it wraps, then compacts the answer's routes. Atomics, a `OnceLock`
        /// read and in-place `DatagramRoute` copies besides the wrapped op (an SDK op, which
        /// catches its own panics), so nothing unwinds out of `extern "C"`.
        const DROP: [[Op; BANK]; LANE_OPS.len()] = [
            drop_row!(0; $($i)+),
            drop_row!(1; $($i)+),
            drop_row!(2; $($i)+),
            drop_row!(3; $($i)+),
            drop_row!(4; $($i)+),
            drop_row!(5; $($i)+),
        ];
    };
}
bank!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);

fn fail_ready(slot: usize, out: *mut c_void) -> RawOutcome {
    READY_CALLS.fetch_add(1, Ordering::SeqCst);
    let failed = RawOutcome::of(Outcome::Failed);
    let (ptr, len) = &READY_TEXT[slot];
    let error = AbiStr {
        ptr: ptr.load(Ordering::Acquire).cast_const(),
        len: len.load(Ordering::Acquire),
    };
    let out = out.cast::<OutHead>();
    if !out.is_null() {
        // SAFETY: READY lends the host's own complete `OutHead`, exclusively, for this call; the
        // text is a `&'static str` stored before the door was published (Release/Acquire).
        unsafe {
            (*out).outcome = failed;
            (*out).error = error;
        }
    }
    failed
}

/// The corrupting op of bank slot `bank`: the crossing goes to the op it wraps; on that op's
/// `nth` READY answer that wrote wire bytes, the first of them is flipped (every bit inverted)
/// before the host reads them, as a plugin writing one wrong byte would.
fn corrupt_wire(
    bank: usize,
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    let Some(c) = CORRUPTING[bank].get().copied() else {
        return RawOutcome::of(Outcome::Fault);
    };
    // SAFETY: the host calls this op under the call convention, for the slot the wrapped op sat
    // in; the instance, `in` and `out` are forwarded unchanged to that op, which honours it.
    let answered = unsafe { (c.real)(instance, input, out) };
    if answered.outcome() != Outcome::Ready || input.is_null() || out.is_null() {
        return answered;
    }
    // SAFETY: the host lends framer slot `c.slot` its own complete `in` of that slot's type for
    // the crossing, and each of them holds the op's `FramerSink`.
    let sink: FramerSink = unsafe {
        match c.slot {
            framer::BEGIN => (*input.cast::<BeginIn>()).sink,
            framer::INGEST => (*input.cast::<IngestIn>()).sink,
            framer::EMIT => (*input.cast::<EmitIn>()).sink,
            framer::ENCODE => (*input.cast::<EncodeIn>()).sink,
            framer::REFUSE => (*input.cast::<RefuseIn>()).sink,
            framer::FINISH => (*input.cast::<FinishIn>()).sink,
            framer::DETACH | framer::TIMER => (*input.cast::<FramingIn>()).sink,
            framer::ADOPT => (*input.cast::<AdoptIn>()).sink,
            _ => return answered,
        }
    };
    // SAFETY: a framer slot's `out` is the host's own complete `FramerOut`, which the wrapped op
    // just answered.
    let wire_len = unsafe { (*out.cast::<FramerOut>()).yielded.wire_len };
    if wire_len == 0 || sink.wire.is_null() || wire_len > sink.wire_cap as u64 {
        return answered;
    }
    if WIRED[bank].fetch_add(1, Ordering::SeqCst).wrapping_add(1) == c.nth {
        // SAFETY: `sink.wire` is the host's buffer of `wire_cap` bytes, lent to this crossing
        // alone; the op answered `wire_len` (at least 1, at most `wire_cap`) of them, so byte 0
        // lies inside it and was written.
        unsafe { *sink.wire = !*sink.wire };
    }
    answered
}

/// The dropping op of bank slot `bank` for the lane op at index `op` of [`LANE_OPS`]: the
/// crossing goes to the op it wraps; on a READY answer to a call lent a lane, every `every`-th
/// media route (counted across this slot's answers) is removed from the lent routes, which are
/// compacted in place, before the host reads them. Any bound that does not hold leaves the answer
/// untouched, so the host's own check judges it.
fn drop_media(
    bank: usize,
    op: usize,
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    let (Some(d), Some(&slot), Some(seen)) = (
        DROPPING.get(bank).and_then(OnceLock::get),
        LANE_OPS.get(op),
        MEDIA.get(bank),
    ) else {
        return RawOutcome::of(Outcome::Fault);
    };
    let Some(Some(real)) = d.real.get(op).copied() else {
        return RawOutcome::of(Outcome::Fault);
    };
    // SAFETY: the host calls this op under the call convention, for the slot the wrapped op sat
    // in; the instance, `in` and `out` are forwarded unchanged to that op, which honours it.
    let answered = unsafe { real(instance, input, out) };
    if answered.outcome() != Outcome::Ready || input.is_null() || out.is_null() {
        return answered;
    }
    // SAFETY: the host lends framer slot `slot` its own complete `in` of that slot's type for the
    // crossing; each of them holds the call's lane (NULL for a stream framer) and its sink.
    let (lane, sink): (*const DatagramLane, FramerSink) = unsafe {
        match slot {
            framer::BEGIN => {
                let i = &*input.cast::<BeginIn>();
                (i.lane, i.sink)
            }
            framer::INGEST => {
                let i = &*input.cast::<IngestIn>();
                (i.lane, i.sink)
            }
            framer::EMIT => {
                let i = &*input.cast::<EmitIn>();
                (i.lane, i.sink)
            }
            framer::FINISH => {
                let i = &*input.cast::<FinishIn>();
                (i.lane, i.sink)
            }
            framer::DETACH | framer::TIMER => {
                let i = &*input.cast::<FramingIn>();
                (i.lane, i.sink)
            }
            _ => return answered,
        }
    };
    if lane.is_null() {
        return answered;
    }
    // SAFETY: a non-NULL lane is the host's own complete `DatagramLane`, lent for the call.
    let lane = unsafe { lane.read() };
    let o = out.cast::<FramerOut>();
    // SAFETY: a framer slot's `out` is the host's own complete `FramerOut`, which the wrapped op
    // just answered.
    let (routes_len, wire_len) = unsafe { ((*o).datagram.routes_len, (*o).yielded.wire_len) };
    let Ok(n) = usize::try_from(routes_len) else {
        return answered;
    };
    let Ok(wire_cap) = u64::try_from(sink.wire_cap) else {
        return answered;
    };
    if n == 0
        || lane.routes.is_null()
        || n > lane.routes_cap
        || sink.wire.is_null()
        || wire_len > wire_cap
    {
        return answered;
    }
    for k in 0..n {
        // SAFETY: `k < n <= routes_cap`: inside the routes buffer the host lent for the call.
        let r = unsafe { lane.routes.add(k).read() };
        if r.offset.checked_add(r.len).is_none_or(|end| end > wire_len) {
            return answered;
        }
    }
    let every = d.every.max(1);
    let mut kept = 0usize;
    for k in 0..n {
        // SAFETY: `k < n <= routes_cap`, as above.
        let r = unsafe { lane.routes.add(k).read() };
        if is_media(&r, sink.wire) {
            let nth = seen.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            if nth % every == 0 {
                DROPPED_MEDIA.fetch_add(1, Ordering::SeqCst);
                continue;
            }
        }
        if kept != k {
            // SAFETY: `kept < k < n <= routes_cap`: inside the routes buffer, which the host lent
            // to this crossing alone and reads only after it returns.
            unsafe { lane.routes.add(kept).write(r) };
        }
        kept += 1;
    }
    let kept = u32::try_from(kept).unwrap_or(routes_len);
    // SAFETY: the host's own `FramerOut`, as above; `kept <= routes_len`.
    unsafe { (*o).datagram.routes_len = kept };
    answered
}

/// Whether route `r` is media: on [`LANE_CLEAR`], and its first byte in 128..=191 (RFC 7983
/// RTP/RTCP). STUN (0..=3), DTLS (20..=63) and every secured route are not.
fn is_media(r: &DatagramRoute, wire: *const u8) -> bool {
    if r.lane != LANE_CLEAR || r.len == 0 {
        return false;
    }
    let Ok(at) = usize::try_from(r.offset) else {
        return false;
    };
    // SAFETY: `offset < offset + len <= wire_len <= wire_cap` (checked by the caller before any
    // read): the byte lies inside the wire the host lent and the op wrote.
    let first = unsafe { *wire.add(at) };
    (128..=191).contains(&first)
}

/// A transport door's ops table, copied.
///
/// # Panics
/// When the door is not a transport's, or its table is shorter than this host's.
fn transport_ops(p: &DoorParts) -> TransportOps {
    assert_eq!(
        p.kind,
        KindCode::Transport as u32,
        "this row corrupts a Transport framer only"
    );
    assert!(!p.ops.is_null(), "the door states no ops table");
    // SAFETY: a real door's ops table is `'static`, readable in full, and states its size in its
    // head.
    let head = unsafe { p.ops.read_unaligned() };
    assert!(
        head.size as usize >= std::mem::size_of::<TransportOps>(),
        "the door's ops table is older than this host's"
    );
    // SAFETY: the door is a transport's (checked above), so its table is a transport `Ops` at
    // least that long; the copy keeps every op of it.
    unsafe { p.ops.cast::<TransportOps>().read_unaligned() }
}

/// The op of framer slot `slot` in `table`; `None` for a slot whose `in` lends no sink.
fn framer_op(table: &mut TransportOps, slot: u32) -> Option<&mut Option<Op>> {
    Some(match slot {
        framer::BEGIN => &mut table.begin,
        framer::INGEST => &mut table.ingest,
        framer::EMIT => &mut table.emit,
        framer::ENCODE => &mut table.encode,
        framer::REFUSE => &mut table.refuse,
        framer::FINISH => &mut table.finish,
        framer::DETACH => &mut table.detach,
        framer::ADOPT => &mut table.adopt,
        framer::TIMER => &mut table.timer,
        _ => return None,
    })
}

/// A real door with one fact changed.
#[derive(Debug, Clone, Copy)]
pub struct Mutant {
    parts: Option<DoorParts>,
    ready_text: Option<&'static str>,
    /// The framer slot whose wire is corrupted, and on which of its wire-writing answers.
    corrupt: Option<(u32, u64)>,
    /// Every how many media routes one is dropped.
    dropping: Option<u64>,
}

impl Mutant {
    /// The door `door` answers, unchanged so far.
    #[must_use]
    pub fn of(door: DoorFn) -> Self {
        let d: &'static Door = door();
        // SAFETY: a `DoorFn` answers a `&'static Door`, readable in full.
        let parts = unsafe { Door::read_parts(d) };
        Self {
            parts: Some(parts),
            ready_text: None,
            corrupt: None,
            dropping: None,
        }
    }

    /// The door states kind ABI version `v`.
    #[must_use]
    pub fn kind_abi(mut self, v: u32) -> Self {
        if let Some(p) = self.parts.as_mut() {
            p.kind_abi = v;
        }
        self
    }

    /// The door states layout fingerprint `l`.
    #[must_use]
    pub fn layout(mut self, l: u64) -> Self {
        if let Some(p) = self.parts.as_mut() {
            p.layout = l;
        }
        self
    }

    /// The door function answers NULL.
    #[must_use]
    pub fn null(mut self) -> Self {
        self.parts = None;
        self
    }

    /// The Statement states version `v` (so it no longer states what its twin states).
    #[must_use]
    pub fn version(self, v: &'static str) -> Self {
        self.restate(|s| s.version = AbiStr::of(v))
    }

    /// A transport's tail states `FramePiece` size `n`.
    ///
    /// # Panics
    /// When the door is not a transport's.
    #[must_use]
    pub fn frame_piece_size(self, n: u32) -> Self {
        self.retail::<TransportTail>(KindCode::Transport, |t| t.frame_piece_size = n)
    }

    /// A plane's tail states answer layout `n`.
    ///
    /// # Panics
    /// When the door is not a plane's.
    #[must_use]
    pub fn answer_layout(self, n: u32) -> Self {
        self.retail::<PlaneTail>(KindCode::Plane, |t| t.answer_layout = n)
    }

    /// The door states no kind tail (STH-ROWS D-3). RED: unchanged yet.
    #[must_use]
    pub fn no_tail(self) -> Self {
        self
    }

    /// The kind tail's head states size `n` (STH-ROWS D-3). RED: unchanged yet.
    #[must_use]
    pub fn tail_size(self, n: u32) -> Self {
        let _ = n;
        self
    }

    /// A plane's tail states no streaming media types (STH-ROWS D-3). RED: unchanged yet.
    #[must_use]
    pub fn no_streaming_types(self) -> Self {
        self
    }

    /// The door's READY answers FAILED with `text` (every crossing counted by
    /// [`Mutant::failed_readies`]).
    #[must_use]
    pub fn failing_ready(mut self, text: &'static str) -> Self {
        self.ready_text = Some(text);
        self
    }

    /// THE CORRUPTING ROW (SDK-SAFE-TEST-HOST §11.6): `door` with its transport framer op `slot`
    /// (`transport::slot::EMIT`, `INGEST`, ...) wrapped, so that the `nth` (from 1) of that op's
    /// READY answers that wrote wire bytes has the first of them flipped (every bit inverted)
    /// before the host reads it. Everything else, the Statement included, is the door's own, so
    /// the mutant is admitted as its door is. The negative control of a conformance run: served
    /// this mutant, the suite must fail.
    ///
    /// # Panics
    /// When `door` is not a transport's, `slot` is not a framer op that writes a sink, the door
    /// serves no op there, or `nth` is 0.
    #[must_use]
    pub fn corrupting(door: DoorFn, slot: u32, nth: u64) -> Self {
        assert!(nth >= 1, "the first wire-writing answer is nth 1");
        let m = Self::of(door);
        if let Some(p) = m.parts.as_ref() {
            let mut table = transport_ops(p);
            let op = framer_op(&mut table, slot)
                .expect("this row corrupts a framer op that writes a sink");
            assert!(
                op.is_some(),
                "the door serves no op in the slot this row corrupts"
            );
        }
        Self {
            corrupt: Some((slot, nth)),
            ..m
        }
    }

    /// THE DROPPING-MEDIA ROW (STH r7.2 erratum §5, §11.6): `door` with every framer op whose `in`
    /// lends a `DatagramLane` wrapped: BEGIN, INGEST, EMIT, FINISH, DETACH and TIMER. After a
    /// wrapped op answers READY, every `every`-th MEDIA route is removed before the host reads the
    /// answer. A media route is one on `LANE_CLEAR` whose first byte, read through the lent
    /// `sink.wire` at the route's offset, is in 128..=191 (RFC 7983 RTP/RTCP). Removal compacts the
    /// lent `routes` array in place and lowers `out.datagram.routes_len`; the wire bytes stay. STUN
    /// (0..=3), DTLS (20..=63) and every `LANE_SECURED` route are kept, so ICE and DTLS complete
    /// and only media dies. The count is per forged mutant, from 1, across answers: `every = 1`
    /// drops all media. A call lent no lane (a stream framer's) is forwarded untouched. The
    /// Statement is the door's own, so the mutant is admitted as its door is. The negative
    /// control of a datagram conformance run (webrtc: media must fail, `connected` must pass).
    ///
    /// # Panics
    /// When `door` is not a transport's or serves none of the six ops, or `every` is 0.
    #[must_use]
    pub fn dropping_media(door: DoorFn, every: u64) -> Self {
        assert!(every >= 1, "the first media route is number 1");
        let m = Self::of(door);
        if let Some(p) = m.parts.as_ref() {
            let mut table = transport_ops(p);
            assert!(
                LANE_OPS
                    .iter()
                    .any(|&slot| framer_op(&mut table, slot).is_some_and(|op| op.is_some())),
                "the door serves none of the framer ops that lend a datagram lane"
            );
        }
        Self {
            dropping: Some(every),
            ..m
        }
    }

    /// Media routes dropped by any [`Mutant::dropping_media`] mutant so far, process-wide.
    #[must_use]
    pub fn dropped_media() -> u64 {
        DROPPED_MEDIA.load(Ordering::SeqCst)
    }

    /// READY crossings into any failing READY so far, process-wide.
    #[must_use]
    pub fn failed_readies() -> u64 {
        READY_CALLS.load(Ordering::SeqCst)
    }

    /// The door with its Statement copied, `edit`ed and leaked.
    fn restate(mut self, edit: impl FnOnce(&mut Statement)) -> Self {
        if let Some(p) = self.parts.as_mut() {
            // SAFETY: a real door's Statement is `'static` and readable in full (its door's
            // contract); the copy keeps every list and string pointer of it.
            let mut st = unsafe { p.statement.read_unaligned() };
            edit(&mut st);
            p.statement = Box::leak(Box::new(st));
        }
        self
    }

    /// The door with its kind tail (a `T`, the tail of `kind`) copied, `edit`ed and leaked.
    fn retail<T: Copy + 'static>(self, kind: KindCode, edit: impl FnOnce(&mut T)) -> Self {
        if let Some(p) = self.parts.as_ref() {
            assert_eq!(p.kind, kind as u32, "this row edits a {kind:?} tail only");
        }
        self.restate(|st| {
            assert!(!st.kind_tail.is_null(), "the door states no kind tail");
            // SAFETY: a real door's kind tail is `'static` and states its own size in its head.
            let size = unsafe { st.kind_tail.read_unaligned() }.size as usize;
            assert!(
                size >= std::mem::size_of::<T>(),
                "the door's tail is older than this host's"
            );
            // SAFETY: the tail is a `T` (its kind was checked above) at least `size_of::<T>()`
            // bytes long; the copy keeps every pointer of it.
            let mut tail = unsafe { st.kind_tail.cast::<T>().read_unaligned() };
            edit(&mut tail);
            st.kind_tail = std::ptr::from_ref(Box::leak(Box::new(tail))).cast::<KindTailHead>();
        })
    }

    /// The forged door function, for the host's `Image::mutant` alone.
    ///
    /// # Panics
    /// When the process has forged all 16 mutants the bank holds.
    #[doc(hidden)]
    #[must_use]
    pub fn door_fn(self) -> RawDoorFn {
        let i = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(i < BANK, "the mutant bank holds {BANK} doors per process");
        let door = self.parts.map_or(std::ptr::null_mut(), |mut p| {
            if let Some(text) = self.ready_text {
                READY_TEXT[i]
                    .0
                    .store(text.as_ptr().cast_mut(), Ordering::Release);
                READY_TEXT[i].1.store(text.len(), Ordering::Release);
                p.ready = Some(READY[i]);
            }
            if let Some((slot, nth)) = self.corrupt {
                let mut table = transport_ops(&p);
                let op = framer_op(&mut table, slot).expect("checked by `corrupting`");
                let real = op.expect("checked by `corrupting`");
                assert!(
                    CORRUPTING[i].set(Corrupting { real, slot, nth }).is_ok(),
                    "each bank slot is forged once"
                );
                *op = Some(CORRUPT[i]);
                p.ops = std::ptr::from_ref(Box::leak(Box::new(table))).cast::<OpsHead>();
            }
            if let Some(every) = self.dropping {
                let mut table = transport_ops(&p);
                let mut real = [None; LANE_OPS.len()];
                let rows = LANE_OPS.iter().zip(real.iter_mut()).zip(DROP.iter());
                for ((&slot, held), row) in rows {
                    let op = framer_op(&mut table, slot).expect("each lane op is a framer op");
                    *held = *op;
                    if op.is_some() {
                        *op = Some(row[i]);
                    }
                }
                assert!(
                    DROPPING[i].set(Dropping { real, every }).is_ok(),
                    "each bank slot is forged once"
                );
                p.ops = std::ptr::from_ref(Box::leak(Box::new(table))).cast::<OpsHead>();
            }
            // SAFETY: the parts are a real `'static` door's: its Statement (or a leaked copy of
            // it with one scalar or `'static` string changed), its ops table (or a leaked copy of
            // it whose one framer op is this bank's corrupting op, or whose served lane ops are
            // this bank's dropping ops, each forwarding every crossing to the op it replaced
            // under the same convention) and its kind, and a replaced READY is this bank's, which
            // honours the call convention. Leaked, so the door is `'static` as a door function's
            // answer must be.
            Box::into_raw(Box::new(unsafe { Door::__from_parts(p) }))
        });
        DOORS[i].store(door, Ordering::Release);
        FNS[i]
    }
}
