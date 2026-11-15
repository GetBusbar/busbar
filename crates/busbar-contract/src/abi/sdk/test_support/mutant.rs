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

use crate::abi::mechanism::call::{AbiStr, OutHead, Outcome, RawOutcome};
use crate::abi::mechanism::door::{Door, DoorFn, DoorParts, KindTailHead, Statement};
use crate::abi::mechanism::KindCode;
use crate::abi::plane::PlaneTail;
use crate::abi::sdk::door::RawDoorFn;
use crate::abi::transport::TransportTail;

/// How many mutants one process may forge: the bank of door functions below.
const BANK: usize = 16;

static NEXT: AtomicUsize = AtomicUsize::new(0);

static DOORS: [AtomicPtr<Door>; BANK] = [const { AtomicPtr::new(std::ptr::null_mut()) }; BANK];

/// The text each slot's failing READY answers: a `&'static str`'s pointer and length.
static READY_TEXT: [(AtomicPtr<u8>, AtomicUsize); BANK] =
    [const { (AtomicPtr::new(std::ptr::null_mut()), AtomicUsize::new(0)) }; BANK];

/// READY crossings into a failing READY, process-wide.
static READY_CALLS: AtomicU64 = AtomicU64::new(0);

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

/// A real door with one fact changed.
#[derive(Debug, Clone, Copy)]
pub struct Mutant {
    parts: Option<DoorParts>,
    ready_text: Option<&'static str>,
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

    /// The door's READY answers FAILED with `text` (every crossing counted by
    /// [`Mutant::failed_readies`]).
    #[must_use]
    pub fn failing_ready(mut self, text: &'static str) -> Self {
        self.ready_text = Some(text);
        self
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
            // SAFETY: the parts are a real `'static` door's: its Statement (or a leaked copy of
            // it with one scalar or `'static` string changed), its ops table and its kind are
            // unchanged, and a replaced READY is this bank's, which honours the call convention.
            // Leaked, so the door is `'static` as a door function's answer must be.
            Box::into_raw(Box::new(unsafe { Door::__from_parts(p) }))
        });
        DOORS[i].store(door, Ordering::Release);
        FNS[i]
    }
}
