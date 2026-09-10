// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-UNIT ARENA THAT SHIPS: the contract's `Arena`, for real, owned by whatever runs one unit.
//!
//! ## What it is
//!
//! The one resource a plugin call is given (`busbar_contract::Ctx::arena`). Four kibibytes of
//! scratch — the contract's own `ARENA_BYTES`, never a second number — plus a small typed region
//! for span-table pairs, owned by the task that runs ONE unit for the length of that unit. It is
//! opened after the unit's frame has arrived and before the plane is asked what the frame means,
//! and nothing on the hot path allocates after that open: the space is two arrays, and the arena
//! only ever splits them.
//!
//! ## Who owns it, and why it is here
//!
//! The kernel's step seam hands a unit `teller::UnitCtx` — key, origin, session, generation, two
//! flags — and no arena, and the one plane unit this root already composes says in its own decode
//! step that the plane read the frame before the loop ran. So the plane call sits ABOVE the loop,
//! in whatever drives a unit,
//! and that driver is the owner: an [`ArenaSpace`] on its own stack, a [`UnitArena`] carved from it,
//! the contract `Ctx` built around that, the plane called, the loop run, the answer encoded, and the
//! space dropped. That driver is the root's, which is why the implementor is the root's too.
//! `docs/design/1.6.0-per-unit-arena.md` carries the argument in full.
//!
//! ## No `unsafe`, and no `reset`
//!
//! The arena holds the unconsumed tail of each region in a `Cell`, takes it out to allocate, splits
//! the head off and puts the shorter tail back. The head is OWNED by the allocating call at the
//! moment it is split, which is what lets it be lent out as a shared borrow of the space with
//! nothing unsafe said. A refusal costs nothing: the tail goes back untouched.
//!
//! There is no `reset`, and there cannot be one. Resetting means reclaiming slices already handed
//! out, which is exactly what the borrow checker refuses, and rightly — a plane may still hold one.
//! Reset at unit end is the space being DROPPED; per-frame reuse on a relay path is one fresh space
//! per frame, the same stack bytes, and no borrow from the last frame able to survive into the next.
//!
//! ## What it is not
//!
//! Not a global allocator, not a pool, not shared between units or threads (`Send`, never `Sync`:
//! a cursor two threads carve at once is not a cursor), and not a plane-visible type — a plane sees
//! `&dyn Arena` through its context and never this module's name.

use std::cell::Cell;

use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Span};

/// The per-unit arena's byte ceiling. The contract's number, so a plugin refused here was refused at
/// the limit the contract told it about.
pub use busbar_contract::ARENA_BYTES;

/// The most pointers one span table allocated out of a unit arena may carry.
///
/// The contract's key ceiling, not a second number: a resolved span table is a declared-pointer map
/// and a fact map is a declared-key map, and a plane that could resolve more pointers than the
/// kernel will carry facts about is describing a body nothing downstream can read.
pub use busbar_contract::MAX_KEYS as ARENA_SPANS;

/// The storage one unit's arena is carved out of.
///
/// Held by the unit's own task — on its stack — and borrowed by exactly one [`UnitArena`] for the
/// length of one unit. Nothing here is shared and nothing here escapes: when the unit ends the
/// space is dropped, and the compiler has already proved that every slice the arena handed out
/// died first.
///
/// Two regions, because the contract asks for two shapes. Bytes and strings come out of `bytes`. A
/// span table is a list of `(&str, Span)` pairs, which is not a layout a safe allocator can carve
/// out of a byte array, so the pairs have a small typed region of their own.
pub struct ArenaSpace<'u> {
    bytes: [u8; ARENA_BYTES],
    spans: [(&'u str, Span); ARENA_SPANS],
}

/// Hand-rolled: the byte region holds a unit's bytes, and a derived `Debug` would print them.
impl std::fmt::Debug for ArenaSpace<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArenaSpace")
            .field("bytes", &ARENA_BYTES)
            .field("spans", &ARENA_SPANS)
            .finish()
    }
}

impl Default for ArenaSpace<'_> {
    fn default() -> Self {
        ArenaSpace::new()
    }
}

impl ArenaSpace<'_> {
    /// A fresh, zeroed space.
    ///
    /// Zeroed HERE rather than at each allocation: the allocator overwrites every byte it hands
    /// out, so the zeroing is what makes a space a previous unit's bytes cannot be read out of, and
    /// it happens once per unit rather than once per allocation.
    #[must_use]
    pub fn new() -> Self {
        ArenaSpace {
            bytes: [0u8; ARENA_BYTES],
            spans: [("", Span::new(0, 0)); ARENA_SPANS],
        }
    }
}

/// The shipping per-unit arena: the contract's [`Arena`], over one [`ArenaSpace`].
///
/// A bump allocator, and therefore `Send` and not `Sync` — which is precisely the clause the
/// contract used to carry and could not honour. See the module header for how it allocates without
/// `unsafe` and why it has no `reset`.
pub struct UnitArena<'u> {
    bytes: Cell<Option<&'u mut [u8]>>,
    spans: Cell<Option<&'u mut [(&'u str, Span)]>>,
    bytes_left: Cell<usize>,
    spans_left: Cell<usize>,
}

/// Hand-rolled for the same reason as the space's: what a reader wants is how much is left.
impl std::fmt::Debug for UnitArena<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitArena")
            .field("bytes_left", &self.bytes_left.get())
            .field("spans_left", &self.spans_left.get())
            .finish()
    }
}

impl<'u> UnitArena<'u> {
    /// Carve an arena out of a unit's space.
    ///
    /// The space is borrowed for the whole of `'u`, so it cannot be reused after this arena is
    /// dropped — which is the rule, not a limitation: reuse is one fresh space per unit.
    #[must_use]
    pub fn new(space: &'u mut ArenaSpace<'u>) -> Self {
        let ArenaSpace { bytes, spans } = space;
        UnitArena {
            bytes_left: Cell::new(bytes.len()),
            spans_left: Cell::new(spans.len()),
            bytes: Cell::new(Some(&mut bytes[..])),
            spans: Cell::new(Some(&mut spans[..])),
        }
    }

    /// How many span-table pairs are left.
    #[must_use]
    pub fn spans_remaining(&self) -> usize {
        self.spans_left.get()
    }

    /// Take `len` bytes off the front of what is left, or refuse.
    ///
    /// A refusal costs the arena nothing: the tail goes back untouched, so a unit that asked for
    /// more than it could have still has everything it had before it asked.
    fn take_bytes(&self, len: usize) -> Result<&'u mut [u8], ArenaBudget> {
        let rest = self.bytes.take().unwrap_or_default();
        if len > rest.len() {
            let remaining = rest.len();
            self.bytes.set(Some(rest));
            return Err(ArenaBudget {
                wanted: len,
                remaining,
            });
        }
        let (head, tail) = rest.split_at_mut(len);
        self.bytes_left.set(tail.len());
        self.bytes.set(Some(tail));
        Ok(head)
    }

    /// Copy a string into the byte region for as long as the space lives.
    ///
    /// The trait's own `alloc_str` narrows this to the caller's borrow; the span table needs the
    /// wider one, because a pointer written into a pair slot has to outlive the call that wrote it.
    fn intern(&self, src: &str) -> Result<&'u str, ArenaBudget> {
        let slot = self.take_bytes(src.len())?;
        slot.copy_from_slice(src.as_bytes());
        let bytes: &'u [u8] = slot;
        // The bytes were copied out of a `&str` one line ago, so this cannot fail. It is answered
        // rather than unwrapped because a unit that cannot allocate must still post: a panic on the
        // frame path loses the hold, and an empty pointer name merely fails to match.
        Ok(std::str::from_utf8(bytes).unwrap_or(""))
    }
}

impl Arena for UnitArena<'_> {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        let slot = self.take_bytes(src.len())?;
        slot.copy_from_slice(src);
        Ok(ArenaBytes::new(slot))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        self.intern(src)
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        let rest = self.spans.take().unwrap_or_default();
        if src.len() > rest.len() {
            let remaining = rest.len();
            self.spans.set(Some(rest));
            return Err(ArenaBudget {
                wanted: src.len(),
                remaining,
            });
        }
        let (head, tail) = rest.split_at_mut(src.len());
        self.spans_left.set(tail.len());
        self.spans.set(Some(tail));
        // The pointers are copied too. The contract says they are the plane's own declared
        // pointers, which are usually static strings, but "usually" is not a lifetime: a pointer
        // that only lived as long as the caller's borrow cannot be written into a slot the space
        // owns. Copying costs the pointer's own bytes out of the same 4 KiB and makes the table
        // outlive the call that built it, which is what the loop then reads it through.
        for (slot, (pointer, span)) in head.iter_mut().zip(src) {
            *slot = (self.intern(pointer)?, *span);
        }
        let table: &[(&str, Span)] = head;
        Ok(table)
    }

    fn remaining(&self) -> usize {
        self.bytes_left.get()
    }
}

#[cfg(test)]
#[path = "tests/arena.rs"]
mod tests;
