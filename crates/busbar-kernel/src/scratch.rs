// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-call scratch pad: grow-on-demand memory the loop threads per call (DECISIONS #41).
//!
//! This is the one resource handle a plugin is given — every byte a plane produces comes out of it.
//! DECISIONS #41 pins its whole behaviour, and this module is that decision in code:
//!
//! > Scratch memory GROWS on demand — never a fixed cap, never a crash. It grows by adding chunks;
//! > it never crashes and never issues a size-based refusal. A measured small size is only a
//! > STARTING size (a perf hint); a big request pays one heap grow instead of crashing. It shrinks
//! > back to the starting size after a big request so no worker permanently hoards. The only
//! > refusal is an abuse-only backstop — a ceiling set absurdly high that only a runaway or attack
//! > could hit — and on trip it cleanly refuses THAT ONE request, never panics.
//!
//! It replaces the fixed-4-KiB `arena::Arena` (kept beside it while the shipped per-call seam is
//! cut over), whose `ArenaExhausted` size-refusal was the live jev bug #41 exists to fix: a ~5 KB
//! response threw on the fixed 4 KiB cap. Here it is a single heap grow and a served request.
//!
//! ## Why bumpalo, and why `forbid(unsafe_code)` still holds
//!
//! The pad is a thin wrapper over [`bumpalo::Bump`], an audited chunk-chaining bump allocator: an
//! allocation that does not fit the current chunk adds a new one, which IS the grow-on-demand the
//! design requires. `forbid(unsafe_code)` on this crate constrains this crate's own source, not its
//! dependencies, and the pad only ever calls bumpalo's SAFE, never-abort `try_*` surface — so a
//! true out-of-memory is a carried refusal, never a process abort.
//!
//! ## Not `Send`/`Sync`, on purpose
//!
//! The runtime is `!Send`, thread-per-core: one pad per worker on its own `LocalSet`, never crossed
//! between threads. So the pad implements the [`Scratch`] contract — which, unlike the retired
//! `Arena` trait, carries no `Send + Sync` bound — and the bump behind it never synchronises.

use std::cell::Cell;

use bumpalo::Bump;
use busbar_contract::bounded::{ScratchBytes, Span};
use busbar_contract::scratch::{Scratch, ScratchRefused};

/// The MEASURED starting size of a scratch pad, in bytes.
///
/// It is the common per-call footprint across the planes — the encoded-frame scratch an llm, mcp,
/// a2a or streaming unit hands back — not a cap: a bigger request grows a chunk. #41 requires it be
/// measured and reported rather than guessed, and it is deliberately the contract's own
/// `SCRATCH_BASE_BYTES` so a plane sized against one constant and a pad sized against the other can
/// never disagree. The number is **4096 bytes (4 KiB)**.
pub const SCRATCH_START_BYTES: usize = busbar_contract::SCRATCH_BASE_BYTES;

/// The abuse-only backstop ceiling, in bytes: **256 MiB**.
///
/// #41: "a ceiling set absurdly high that only a runaway/attack could hit." A legitimate per-call
/// footprint is kilobytes; this is five orders of magnitude above that, so it never refuses real
/// work — it only stops a single runaway or hostile request from growing the pad without bound.
/// On a trip the one request is refused with [`ScratchRefused`] and the pad serves the next call.
pub const SCRATCH_ABUSE_CEILING_BYTES: usize = 256 * 1024 * 1024;

/// A per-call scratch pad: a bump allocator that grows on demand and shrinks back on reset.
#[derive(Debug)]
pub struct ScratchPad {
    /// The chunk-chaining bump. Grows by adding a chunk; allocations borrow it for the call.
    bump: Bump,
    /// The backing capacity of a freshly-started pad, so a reset can tell "we grew" from "we did
    /// not" and shrink only when a big request actually added chunks.
    start_capacity: usize,
    /// Bytes handed out since the last reset — the figure the abuse ceiling is checked against.
    /// A `Cell` because the allocation methods take `&self` (the bump does too).
    used: Cell<usize>,
    /// The abuse ceiling this pad refuses past.
    ceiling: usize,
    /// How many times the pad has been reset — a test uses this to prove per-frame reset.
    resets: u64,
}

impl Default for ScratchPad {
    fn default() -> Self {
        ScratchPad::new()
    }
}

impl ScratchPad {
    /// A fresh pad at the measured starting size, with the standard abuse ceiling.
    #[must_use]
    pub fn new() -> Self {
        ScratchPad::with_ceiling(SCRATCH_ABUSE_CEILING_BYTES)
    }

    /// A fresh pad with a chosen abuse ceiling. The starting size is always the measured one; only
    /// the runaway backstop moves, which is what a test needs to exercise the backstop cheaply.
    #[must_use]
    pub fn with_ceiling(ceiling: usize) -> Self {
        let bump = Bump::with_capacity(SCRATCH_START_BYTES);
        let start_capacity = bump.allocated_bytes();
        ScratchPad {
            bump,
            start_capacity,
            used: Cell::new(0),
            ceiling,
            resets: 0,
        }
    }

    /// The pad's current backing capacity in bytes. Grows past [`SCRATCH_START_BYTES`] when a big
    /// request adds chunks, and returns to the starting capacity after a reset that follows one.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bump.allocated_bytes()
    }

    /// How many resets have happened over the pad's life.
    #[must_use]
    pub fn resets(&self) -> u64 {
        self.resets
    }

    /// Give the pad back to itself, and shrink it back to the starting size if it grew.
    ///
    /// The loop calls this per relayed frame on an open unit and at unit end otherwise. If nothing
    /// grew the pad past its starting chunk the reset is cheap — the chunk is kept and only the
    /// cursor moves. If a big request added chunks the pad is rebuilt at the starting size, so a
    /// worker that served one large request does not hoard that memory for the rest of its life.
    pub fn reset(&mut self) {
        if self.bump.allocated_bytes() > self.start_capacity {
            self.bump = Bump::with_capacity(SCRATCH_START_BYTES);
            self.start_capacity = self.bump.allocated_bytes();
        } else {
            self.bump.reset();
        }
        self.used.set(0);
        self.resets = self.resets.saturating_add(1);
    }

    /// The abuse-backstop check: refuse the ONE request that would carry the pad past its ceiling.
    fn guard(&self, wanted: usize) -> Result<(), ScratchRefused> {
        if self.used.get().saturating_add(wanted) > self.ceiling {
            return Err(ScratchRefused {
                wanted,
                ceiling: self.ceiling,
            });
        }
        Ok(())
    }

    /// Note a successful allocation against the ceiling.
    fn charge(&self, wanted: usize) {
        self.used.set(self.used.get().saturating_add(wanted));
    }

    /// The abuse-ceiling refusal for a request bumpalo itself could not honour (true OOM).
    fn oom(&self, wanted: usize) -> ScratchRefused {
        ScratchRefused {
            wanted,
            ceiling: self.ceiling,
        }
    }
}

impl Scratch for ScratchPad {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ScratchBytes<'a>, ScratchRefused> {
        self.guard(src.len())?;
        let dst = self
            .bump
            .try_alloc_slice_copy(src)
            .map_err(|_| self.oom(src.len()))?;
        self.charge(src.len());
        Ok(ScratchBytes::new(dst))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ScratchRefused> {
        self.guard(src.len())?;
        let dst = self
            .bump
            .try_alloc_str(src)
            .map_err(|_| self.oom(src.len()))?;
        self.charge(src.len());
        Ok(dst)
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ScratchRefused> {
        let wanted = std::mem::size_of_val(src);
        self.guard(wanted)?;
        let dst = self
            .bump
            .try_alloc_slice_copy(src)
            .map_err(|_| self.oom(wanted))?;
        self.charge(wanted);
        Ok(dst)
    }

    fn remaining(&self) -> usize {
        self.ceiling.saturating_sub(self.used.get())
    }
}
