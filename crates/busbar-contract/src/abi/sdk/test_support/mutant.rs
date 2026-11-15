// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MUTANT ROW (SDK-SAFE-TEST-HOST §3.4): a real door with one fact changed, for a negative
//! load case. It answers a [`RawDoorFn`] (never a `DoorFn`, which cannot be NULL), and the test
//! hands it only to the host's `Image::mutant`, so the raw door never reaches test code.

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::abi::mechanism::door::{Door, DoorFn, DoorParts};
use crate::abi::sdk::door::RawDoorFn;

/// How many mutants one process may forge: the bank of door functions below.
const BANK: usize = 16;

static NEXT: AtomicUsize = AtomicUsize::new(0);

static DOORS: [AtomicPtr<Door>; BANK] = [const { AtomicPtr::new(std::ptr::null_mut()) }; BANK];

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
    };
}
bank!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);

/// A real door with one fact changed.
#[derive(Debug, Clone, Copy)]
pub struct Mutant {
    parts: Option<DoorParts>,
}

impl Mutant {
    /// The door `door` answers, unchanged so far.
    #[must_use]
    pub fn of(door: DoorFn) -> Self {
        let d: &'static Door = door();
        // SAFETY: a `DoorFn` answers a `&'static Door`, readable in full.
        let parts = unsafe { Door::read_parts(d) };
        Self { parts: Some(parts) }
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

    /// The forged door function, for the host's `Image::mutant` alone.
    ///
    /// # Panics
    /// When the process has forged all 16 mutants the bank holds.
    #[doc(hidden)]
    #[must_use]
    pub fn door_fn(self) -> RawDoorFn {
        let i = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(i < BANK, "the mutant bank holds {BANK} doors per process");
        let door = self.parts.map_or(std::ptr::null_mut(), |p| {
            // SAFETY: the parts are a real `'static` door's: its Statement and ops table are that
            // door's `'static` data and its kind is unchanged. Only a version or layout number
            // differs, which the host checks before it reads anything they govern. Leaked, so the
            // door is `'static` as a door function's answer must be.
            Box::into_raw(Box::new(unsafe { Door::__from_parts(p) }))
        });
        DOORS[i].store(door, Ordering::Release);
        FNS[i]
    }
}
