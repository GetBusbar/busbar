// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::Cell;

use bumpalo::Bump;
use busbar_contract::bounded::{ScratchBytes, Span};
use busbar_contract::scratch::{Scratch, ScratchRefused};

pub const SCRATCH_START_BYTES: usize = busbar_contract::SCRATCH_BASE_BYTES;

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
    #[must_use]
    pub fn new() -> Self {
        ScratchPad::with_ceiling(SCRATCH_ABUSE_CEILING_BYTES)
    }

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

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bump.allocated_bytes()
    }

    #[must_use]
    pub fn resets(&self) -> u64 {
        self.resets
    }

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

    fn copy_in<'a, T: ?Sized>(
        &'a self,
        wanted: usize,
        alloc: impl FnOnce(&'a Bump) -> Result<&'a mut T, bumpalo::AllocErr>,
    ) -> Result<&'a mut T, ScratchRefused> {
        let refused = ScratchRefused {
            wanted,
            ceiling: self.ceiling,
        };
        if self.used.get().saturating_add(wanted) > self.ceiling {
            return Err(refused);
        }
        let dst = alloc(&self.bump).map_err(|_| refused)?;
        self.used.set(self.used.get().saturating_add(wanted));
        Ok(dst)
    }
}

impl Scratch for ScratchPad {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ScratchBytes<'a>, ScratchRefused> {
        let dst = self.copy_in(src.len(), |bump| bump.try_alloc_slice_copy(src))?;
        Ok(ScratchBytes::new(dst))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ScratchRefused> {
        let dst = self.copy_in(src.len(), |bump| bump.try_alloc_str(src))?;
        Ok(dst)
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ScratchRefused> {
        let dst = self.copy_in(std::mem::size_of_val(src), |bump| {
            bump.try_alloc_slice_copy(src)
        })?;
        Ok(dst)
    }

    fn remaining(&self) -> usize {
        self.ceiling.saturating_sub(self.used.get())
    }
}
