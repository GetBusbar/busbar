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

use busbar_caps::ReasonCode;
use busbar_contract::bounded::MAX_KEYS;

use crate::grammar::{ArrivalLocation, MaskKind, Span};

/// The arena's own vocabulary, named here rather than restated.
///
/// The trait, its refusal and its byte handle are the contract's, for the same reason the size
/// below is: a caller that reaches the arena through this module gets the ABI's own types, so
/// there is no kernel-shaped near-copy of any of them for a plugin's answer to be measured against.
pub use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes};

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

/// THE KERNEL'S SECOND BUMP BUFFER IS GONE, and what is below is what replaced it.
///
/// There were two 4 KiB arenas in this tree and neither was production. One was the contract's
/// `Arena` trait — the ONE resource handle a plugin is given — with sixteen implementors, every
/// one a test double that handed out `Box::leak`ed bytes. The other was this module's own `Arena`:
/// a fixed buffer, a bump cursor, a `Span`-shaped `take`/`push`/`read`/`write` API and its own
/// `ArenaFull` refusal, 116 lines that implemented nothing of the contract and were called by
/// nothing outside this crate's own test. It carried the claim — "a session that relays for an
/// hour uses the same 4 KiB it used at its first frame" — that no arena in the tree could keep.
///
/// [`ArenaBuf`] and [`UnitArena`] are the one arena, and they implement the contract's trait. The
/// zeroing the old `take` did on the way out is met by construction instead: there is no
/// take-a-span-and-write-into-it-later call on the contract's arena, so an allocation is handed
/// back exactly the bytes copied into it and a short write cannot expose the tail of the frame
/// before. `busbar-kernel/tests/arena_reuse.rs` is the measurement.
///
/// The bytes one unit's arena runs over: 4 KiB, allocated once, given back to itself per frame.
///
/// The arena is a BORROW of this rather than a value that owns its own bytes, and the reason is in
/// [`Arena`]'s own signature: the two allocators take `&self` and hand back slices that live as
/// long as that borrow, so the bytes they lend must come from memory somebody else owns for at
/// least as long. Every implementor written against this trait before this one handed out
/// `Box::leak`ed bytes — a fresh allocation on every call and a unit that never gives its scratch
/// space back — because a value that owns its buffer cannot lend it out through a shared reference
/// without reaching for unsafe, and this crate forbids that.
///
/// Resetting is re-leasing. [`lease`] takes `&mut self`, so the previous lease and every byte it
/// lent are provably over before the next one starts, and the cursor goes back to zero over the
/// SAME bytes. That is what makes "a session that relays for an hour uses the same 4 KiB it used
/// at its first frame" a borrow rule the compiler carries rather than a promise a reader is asked
/// to take on trust.
///
/// [`lease`]: ArenaBuf::lease
#[derive(Debug)]
pub struct ArenaBuf {
    bytes: Box<[u8; ARENA_BYTES]>,
    leases: u64,
    high_water: usize,
}

impl Default for ArenaBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl ArenaBuf {
    /// A fresh buffer. One allocation, made where the unit is set up and never on the frame path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: Box::new([0u8; ARENA_BYTES]),
            leases: 0,
            high_water: 0,
        }
    }

    /// Hand the whole buffer to one frame's arena, and count the reset.
    ///
    /// The span table is the caller's own and not a field here, for the one reason a byte buffer
    /// is not enough: a resolved span table is `(&str, Span)` PAIRS, so a table stored on this
    /// value would have to name the lease's lifetime in this type — which pins the buffer to its
    /// first lease and makes the second one uncompilable. [`span_slab`] builds one.
    pub fn lease<'u>(&'u mut self, spans: &'u mut [(&'u str, Span)]) -> UnitArena<'u> {
        self.leases = self.leases.saturating_add(1);
        let bytes: &'u mut [u8] = &mut self.bytes[..];
        UnitArena {
            cursor: std::sync::Mutex::new(Cursor {
                bytes,
                spans,
                used: 0,
                high_water: &mut self.high_water,
            }),
        }
    }

    /// How many times this buffer has been given back to itself.
    ///
    /// One per lease, and a lease is one frame. The number a proof uses to say the reset happened
    /// as many times as frames went by.
    #[must_use]
    pub fn resets(&self) -> u64 {
        self.leases
    }

    /// The most bytes any one lease of this buffer ever held at once.
    ///
    /// Across every lease, never cleared. A buffer whose high-water stops moving after the first
    /// frame is a buffer that is being reused; one that climbs is one that is being re-allocated
    /// under a different name.
    #[must_use]
    pub fn high_water(&self) -> usize {
        self.high_water
    }
}

/// A span table for one lease, of the width a fact map is bounded to.
///
/// Sized by [`MAX_KEYS`], because a resolved pointer table and a fact map are the same shape of
/// thing — a plane's declared keys — and a second, differently-sized ceiling for the same
/// declaration is two numbers that have to agree and nothing making them.
#[must_use]
pub fn span_slab<'u>() -> [(&'u str, Span); MAX_KEYS] {
    [("", Span::new(0, 0)); MAX_KEYS]
}

/// The bump cursor over one lease of an [`ArenaBuf`].
#[derive(Debug)]
struct Cursor<'u> {
    bytes: &'u mut [u8],
    spans: &'u mut [(&'u str, Span)],
    used: usize,
    high_water: &'u mut usize,
}

impl<'u> Cursor<'u> {
    /// Split `len` bytes off the front of what is left, or say how much was left.
    fn take(&mut self, len: usize) -> Result<&'u mut [u8], ArenaBudget> {
        let free = std::mem::take(&mut self.bytes);
        if len > free.len() {
            let remaining = free.len();
            self.bytes = free;
            return Err(ArenaBudget {
                wanted: len,
                remaining,
            });
        }
        let (head, tail) = free.split_at_mut(len);
        self.bytes = tail;
        self.used += len;
        if self.used > *self.high_water {
            *self.high_water = self.used;
        }
        Ok(head)
    }
}

/// The per-unit arena, as the one resource handle a plugin is given.
///
/// A bump cursor over one lease of an [`ArenaBuf`]. There is no free: the whole 4 KiB comes back
/// at once when the lease ends, which is the frame boundary on a relayed unit and the unit's end
/// otherwise.
#[derive(Debug)]
pub struct UnitArena<'u> {
    cursor: std::sync::Mutex<Cursor<'u>>,
}

impl<'u> UnitArena<'u> {
    /// How many bytes this lease has taken so far.
    #[must_use]
    pub fn used(&self) -> usize {
        self.locked().used
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Cursor<'u>> {
        // A cursor is `Copy` scalars and three borrows: nothing it does can unwind, so the only
        // way past this is a panic somewhere else while the lock is held, and there is no
        // somewhere else — every body below is straight-line and total.
        self.cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<'u> Arena for UnitArena<'u> {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        let dst = self.locked().take(src.len())?;
        dst.copy_from_slice(src);
        Ok(ArenaBytes::new(dst))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        let dst = self.locked().take(src.len())?;
        dst.copy_from_slice(src.as_bytes());
        // Total: `dst` is the bytes of `src`, copied on the line above and read by nothing in
        // between, so the only string this can be is the one that went in.
        Ok(std::str::from_utf8(dst).unwrap_or(""))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        let mut cursor = self.locked();
        let free = std::mem::take(&mut cursor.spans);
        if src.len() > free.len() {
            let remaining = free.len();
            cursor.spans = free;
            return Err(ArenaBudget {
                wanted: src.len(),
                remaining,
            });
        }
        let (head, tail) = free.split_at_mut(src.len());
        cursor.spans = tail;
        for (slot, (pointer, span)) in head.iter_mut().zip(src) {
            // The KEY is copied in, and that is not an optimisation missed. A slot in this table
            // is typed at the lease's lifetime; the pointer the caller hands over is borrowed at
            // its own, which is shorter, so storing it would be storing a reference that outlives
            // what it points at. A declared pointer is a handful of bytes and the table is bounded
            // at MAX_KEYS of them.
            let copied = cursor.take(pointer.len())?;
            copied.copy_from_slice(pointer.as_bytes());
            *slot = (std::str::from_utf8(copied).unwrap_or(""), *span);
        }
        Ok(head)
    }

    fn remaining(&self) -> usize {
        self.locked().bytes.len()
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
