// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-unit scratch space, and the slab a credential is hidden in.
//!
//! Two small things, both about memory the loop is allowed to touch.
//!
//! The **arena** is 4 KiB per unit, and it is the ONE resource handle a plugin is given. On the
//! relay path of an open unit it is reset per frame: each encoded frame lives in it only until the
//! frame is queued to the connection, so a session that relays for an hour uses the same 4 KiB it
//! used at its first frame. Bodies never live here — they live in the connection's own slab and the
//! spill buffer — so the arena can never refuse a request that would otherwise have been served.
//!
//! The **credential slab** is per connection. When a credential is found in arriving bytes, its
//! span is copied out into the slab and the bytes where it sat are overwritten with same-length
//! fill. After that the cursor a plane sees has no credential in it, which is why "a plane never
//! sees a credential" is a property of the bytes rather than a rule planes are asked to follow.

use std::cell::Cell;

use busbar_caps::ReasonCode;
use busbar_contract::bounded::{ArenaBudget, ArenaBytes};

use crate::grammar::{ArrivalLocation, MaskKind, Span};

/// The per-unit arena, pinned by the design at 4 KiB.
///
/// The contract's number, not a second copy of it. A plugin allocates against the contract's
/// ceiling and the kernel sizes the buffer against this one, so two independently-maintained
/// constants that happened to agree today would be a plugin refused at a limit the kernel does not
/// have — or worse, a buffer smaller than what the contract told the plugin it could ask for.
pub use busbar_contract::ARENA_BYTES;

/// The per-connection cursor cap, which the credential slab is counted inside. Also the contract's.
pub use busbar_contract::MAX_CURSOR_BYTES as CURSOR_CAP_BYTES;

/// The byte a masked span is overwritten with.
///
/// Same length in, same length out: every offset a plane or a locator later computes over the
/// cursor still points where it pointed, which is what makes masking invisible to everything
/// downstream.
pub const FILL_BYTE: u8 = b'*';

/// The arena said no: the unit asked for more scratch space than it has left.
///
/// Carried rather than panicked, because the loop turns it into `Failed(step, ArenaBudget)` and
/// posts, and a unit that cannot post is worse than one that cannot encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaFull {
    /// How many bytes were asked for.
    pub requested: usize,
    /// How many were left.
    pub remaining: usize,
}

impl ArenaFull {
    /// The reason the loop ends the unit with.
    pub fn reason(self) -> ReasonCode {
        ReasonCode::ArenaBudget
    }
}

impl std::fmt::Display for ArenaFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "arena exhausted: {} bytes wanted, {} left",
            self.requested, self.remaining
        )
    }
}

impl std::error::Error for ArenaFull {}

/// One unit's 4 KiB of scratch space: a fixed buffer and a bump cursor.
///
/// There is no free. There is only [`Arena::reset`], and the loop calls it at exactly two moments:
/// after each relayed frame on an open unit, and at the end of the unit otherwise.
#[derive(Debug)]
pub struct Arena {
    buf: [u8; ARENA_BYTES],
    used: usize,
    /// How many times the arena has been reset — the number a test uses to prove per-frame reset.
    resets: u64,
}

impl Default for Arena {
    fn default() -> Self {
        Arena::new()
    }
}

impl Arena {
    /// A fresh, empty arena. No heap: the buffer is the value.
    pub fn new() -> Self {
        Arena {
            buf: [0u8; ARENA_BYTES],
            used: 0,
            resets: 0,
        }
    }

    /// How many bytes are in use.
    pub fn used(&self) -> usize {
        self.used
    }

    /// How many bytes are left.
    pub fn remaining(&self) -> usize {
        ARENA_BYTES - self.used
    }

    /// How many times this arena has been reset.
    pub fn resets(&self) -> u64 {
        self.resets
    }

    /// Give the arena back to itself. Nothing is freed; the cursor moves to the start, and the
    /// bytes the next frame is handed are cleared as it takes them.
    pub fn reset(&mut self) {
        self.used = 0;
        self.resets = self.resets.saturating_add(1);
    }

    /// Take `len` bytes of zeroed space, and say where they are.
    ///
    /// The zeroing happens HERE, where the promise is made, and not at the reset that hands the
    /// buffer back. `reset` only moves the cursor, so a span taken over ground a previous frame
    /// used still held that frame's bytes; a unit that then wrote less into the span than it asked
    /// for could read the remainder straight back out, which is one connection's bytes surfacing
    /// inside another's buffer. Clearing on the way out costs one pass over the span a unit was
    /// about to write anyway, and it is the only point both the reset path and a fresh arena go
    /// through.
    pub fn take(&mut self, len: usize) -> Result<Span, ArenaFull> {
        if len > self.remaining() {
            return Err(ArenaFull {
                requested: len,
                remaining: self.remaining(),
            });
        }
        let span = Span::new(self.used, self.used + len);
        self.buf[span.start..span.end].fill(0);
        self.used += len;
        Ok(span)
    }

    /// Copy `bytes` into the arena and say where they landed.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Span, ArenaFull> {
        let span = self.take(bytes.len())?;
        self.buf[span.start..span.end].copy_from_slice(bytes);
        Ok(span)
    }

    /// Read back what is at a span.
    pub fn read(&self, span: Span) -> &[u8] {
        &self.buf[span.start..span.end.min(ARENA_BYTES)]
    }

    /// Write into a span the arena handed out.
    pub fn write(&mut self, span: Span, bytes: &[u8]) -> Result<(), ArenaFull> {
        if bytes.len() > span.len() {
            return Err(ArenaFull {
                requested: bytes.len(),
                remaining: span.len(),
            });
        }
        self.buf[span.start..span.start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// The most pointers one span table allocated out of a unit arena may carry.
///
/// The contract's key ceiling, not a second number: a resolved span table is a declared-pointer map
/// and a fact map is a declared-key map, and a plane that could resolve more pointers than the
/// kernel will carry facts about is describing a body nothing downstream can read. Spelling a
/// separate figure here is how the two come to disagree.
pub use busbar_contract::MAX_KEYS as ARENA_SPANS;

/// The storage one unit's arena is carved out of.
///
/// Held by the unit's own task — on its stack, or boxed once by a pool — and borrowed by exactly
/// one [`UnitArena`] for the length of one unit. Nothing here is shared and nothing here escapes:
/// when the unit ends the space is dropped, and the compiler has already proved that every slice
/// the arena handed out died first.
///
/// Two regions, because the contract asks for two shapes. Bytes and strings come out of `bytes`.
/// A span table is a list of `(&str, Span)` pairs, which is not a byte layout a safe allocator can
/// carve out of a byte array, so the pairs have a small typed region of their own.
#[derive(Debug)]
pub struct ArenaSpace<'u> {
    bytes: [u8; ARENA_BYTES],
    spans: [(&'u str, Span); ARENA_SPANS],
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
    /// out, so the zeroing is what makes a space that a previous unit's bytes could not be read
    /// out of, and it happens once per unit rather than once per allocation.
    pub fn new() -> Self {
        ArenaSpace {
            bytes: [0u8; ARENA_BYTES],
            spans: [("", Span::new(0, 0)); ARENA_SPANS],
        }
    }
}

/// The shipping per-unit arena: the contract's `Arena`, for real.
///
/// A bump allocator, and therefore not `Sync` — which is precisely the clause the contract used to
/// carry and could not honour. It holds the unconsumed tail of each region in a `Cell`, takes the
/// tail out to allocate, splits the head off and puts the shorter tail back. That is the whole
/// trick, and it needs no `unsafe`: the head is OWNED by the allocating call at the moment it is
/// split, so handing it out as a shared borrow of the space is something safe Rust can already say.
///
/// There is no `reset`. Resetting would mean reclaiming slices already handed out, which is exactly
/// what the borrow checker refuses, and correctly — a plane may still be holding one. Per-frame
/// reset on a relay path is one fresh [`ArenaSpace`] per frame instead: the same stack bytes, the
/// same 4 KiB resident, and no borrow from the last frame able to survive into the next.
pub struct UnitArena<'u> {
    bytes: Cell<Option<&'u mut [u8]>>,
    spans: Cell<Option<&'u mut [(&'u str, Span)]>>,
    bytes_left: Cell<usize>,
    spans_left: Cell<usize>,
}

/// Hand-rolled: the regions hold a unit's bytes, and a derived `Debug` would print them. What a
/// reader wants from one of these is how much is left, which is what this says.
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
    pub fn new(space: &'u mut ArenaSpace<'u>) -> Self {
        let ArenaSpace { bytes, spans } = space;
        UnitArena {
            bytes_left: Cell::new(bytes.len()),
            spans_left: Cell::new(spans.len()),
            bytes: Cell::new(Some(&mut bytes[..])),
            spans: Cell::new(Some(&mut spans[..])),
        }
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

impl busbar_contract::bounded::Arena for UnitArena<'_> {
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
        // outlive the call that built it, which is what the kernel then reads it through.
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

/// Where a masked credential ended up in the slab.
///
/// A handle, not the bytes: the auth unit asks the slab for the bytes when it needs them, and
/// nothing else ever holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskedSpan {
    offset: usize,
    len: usize,
}

impl MaskedSpan {
    /// How many bytes were taken out of the cursor.
    pub fn len(self) -> usize {
        self.len
    }

    /// Whether nothing was masked — the client-certificate form, which masks no bytes at all.
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// The per-connection credential slab.
///
/// One allocation, made when the connection is accepted, sized by the cursor cap. Nothing on the
/// frame path grows it: an oversize credential is refused with `CredentialBudget`, which is a
/// different answer from `CursorBudget` on purpose — the slab is full, not the cursor.
#[derive(Debug)]
pub struct CredentialSlab {
    buf: Vec<u8>,
    cap: usize,
}

impl CredentialSlab {
    /// A slab bounded by the cursor cap.
    pub fn new() -> Self {
        CredentialSlab::with_capacity(CURSOR_CAP_BYTES)
    }

    /// A slab bounded by `cap` bytes, allocated now so the frame path never allocates.
    pub fn with_capacity(cap: usize) -> Self {
        CredentialSlab {
            buf: Vec::with_capacity(cap),
            cap,
        }
    }

    /// How many bytes of credential this connection is holding.
    pub fn used(&self) -> usize {
        self.buf.len()
    }

    /// How many are left.
    pub fn remaining(&self) -> usize {
        self.cap - self.buf.len()
    }

    /// Copy a span of the cursor into the slab and fill the hole it left.
    ///
    /// The returned handle is the only way back to the bytes. The cursor comes back the same
    /// length it went in.
    pub fn mask(&mut self, cursor: &mut [u8], span: Span) -> Result<MaskedSpan, ReasonCode> {
        if span.end > cursor.len() {
            return Err(ReasonCode::CursorBudget);
        }
        if span.len() > self.remaining() {
            return Err(ReasonCode::CredentialBudget);
        }
        let offset = self.buf.len();
        self.buf.extend_from_slice(&cursor[span.start..span.end]);
        for byte in &mut cursor[span.start..span.end] {
            *byte = FILL_BYTE;
        }
        Ok(MaskedSpan {
            offset,
            len: span.len(),
        })
    }

    /// Mask a span the way the location says to.
    ///
    /// Per form: a span form is filled to the same length; a client certificate is not in the bytes
    /// at all and nothing is masked; a signature has only its own span masked; a handshake prefix
    /// is masked up to its bound and the rest of the frame is left alone. The location is taken
    /// whole rather than as its mask kind alone, because the prefix bound is declared on the
    /// location and reading the two apart is how they come to disagree.
    pub fn mask_as(
        &mut self,
        cursor: &mut [u8],
        span: Span,
        location: &ArrivalLocation,
    ) -> Result<MaskedSpan, ReasonCode> {
        match location.mask() {
            MaskKind::Nothing => Ok(MaskedSpan {
                offset: self.buf.len(),
                len: 0,
            }),
            MaskKind::SameLengthFill | MaskKind::SignatureSpan => self.mask(cursor, span),
            MaskKind::BoundedPrefix => {
                // Exhaustive over the location forms, with no catch-all: the bound is declared on
                // the location, only the handshake form declares one, and a form that masks by
                // bounded prefix without naming its bound would be masking NOTHING — the
                // credential left in the cursor, with nothing failing to say so. Named in full,
                // such a form stops compiling here instead.
                let max_bytes = match location {
                    ArrivalLocation::HandshakeFrames { max_bytes, .. } => *max_bytes as usize,
                    ArrivalLocation::Header(_)
                    | ArrivalLocation::Query(_)
                    | ArrivalLocation::PathSegment(_)
                    | ArrivalLocation::FirstFrameJsonPointer(_)
                    | ArrivalLocation::ClientCert
                    | ArrivalLocation::Signed { .. } => 0,
                };
                let bounded = Span::new(span.start, span.end.min(span.start + max_bytes));
                self.mask(cursor, bounded)
            }
        }
    }

    /// Read a masked credential back. The auth unit does this; nothing else has a handle.
    pub fn read(&self, masked: MaskedSpan) -> &[u8] {
        &self.buf[masked.offset..masked.offset + masked.len]
    }

    /// Forget everything. Called when a connection upgrades in band, because the facts and the
    /// principal are cleared there too, and a credential that survived would outlive its context.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

impl Default for CredentialSlab {
    fn default() -> Self {
        CredentialSlab::new()
    }
}
