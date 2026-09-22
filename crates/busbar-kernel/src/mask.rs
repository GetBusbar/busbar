// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dead fixed-size scratch allocator kept for reference, and the slab a credential is hidden
//! in.
//!
//! Two small things, both about memory the loop is allowed to touch.
//!
//! [`FixedScratch`] is the PRE-DECISIONS-#41 4-KiB-per-unit, fixed-cap, size-refusing allocator —
//! the design #41 kills outright ("kills the 'arena' model + its fixed-4KiB-refuse design"). It has
//! no caller anywhere in this tree outside its own tests; the live per-call scratch handle is
//! [`crate::scratch::ScratchPad`], which grows on demand and never refuses for size. This type is
//! kept only as a reference for the still-open cutover (see `crate::scratch`'s module docs) and
//! should be deleted once that cutover lands.
//!
//! The **credential slab** is per connection. When a credential is found in arriving bytes, its
//! span is copied out into the slab and the bytes where it sat are overwritten with same-length
//! fill. After that the cursor a plane sees has no credential in it, which is why "a plane never
//! sees a credential" is a property of the bytes rather than a rule planes are asked to follow.

use busbar_contract::caps::ReasonCode;
use zeroize::Zeroize;

use crate::grammar::{ArrivalLocation, MaskKind, Span};

/// The fixed size [`FixedScratch`] was pinned at, in bytes.
///
/// The contract's number, not a second copy of it — [`busbar_contract::SCRATCH_BASE_BYTES`] is the
/// same measured starting size [`crate::scratch::ScratchPad`] uses, kept here only so this dead
/// type still compiles against the number the design pinned it to.
pub use busbar_contract::SCRATCH_BASE_BYTES as FIXED_SCRATCH_BYTES;

/// The per-connection cursor cap, which the credential slab is counted inside. Also the contract's.
pub use busbar_contract::MAX_CURSOR_BYTES as CURSOR_CAP_BYTES;

/// The byte a masked span is overwritten with.
///
/// Same length in, same length out: every offset a plane or a locator later computes over the
/// cursor still points where it pointed, which is what makes masking invisible to everything
/// downstream.
pub const FILL_BYTE: u8 = b'*';

/// The fixed allocator said no: the unit asked for more scratch space than it has left.
///
/// Carried rather than panicked, because the loop turns it into `Failed(step, ScratchExhausted)` and
/// posts, and a unit that cannot post is worse than one that cannot encode. (`ScratchExhausted` is the
/// sealed, wire-spelled [`ReasonCode`] variant DECISIONS #9/#10 keeps byte-identical; only this
/// dead allocator's own Rust vocabulary is renamed.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedScratchFull {
    /// How many bytes were asked for.
    pub requested: usize,
    /// How many were left.
    pub remaining: usize,
}

impl FixedScratchFull {
    /// The reason the loop ends the unit with.
    pub fn reason(self) -> ReasonCode {
        ReasonCode::ScratchExhausted
    }
}

impl std::fmt::Display for FixedScratchFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fixed scratch exhausted: {} bytes wanted, {} left",
            self.requested, self.remaining
        )
    }
}

impl std::error::Error for FixedScratchFull {}

/// One unit's 4 KiB of fixed, size-refusing scratch space: a fixed buffer and a bump cursor.
///
/// DEAD — see the module docs. There is no free. There is only [`FixedScratch::reset`], and (when
/// this type was live) the loop called it at exactly two moments: after each relayed frame on an
/// open unit, and at the end of the unit otherwise.
#[derive(Debug)]
pub struct FixedScratch {
    buf: [u8; FIXED_SCRATCH_BYTES],
    used: usize,
    /// How many times this has been reset — the number a test uses to prove per-frame reset.
    resets: u64,
}

impl Default for FixedScratch {
    fn default() -> Self {
        FixedScratch::new()
    }
}

impl FixedScratch {
    /// A fresh, empty allocator. No heap: the buffer is the value.
    pub fn new() -> Self {
        FixedScratch {
            buf: [0u8; FIXED_SCRATCH_BYTES],
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
        FIXED_SCRATCH_BYTES - self.used
    }

    /// How many times this has been reset.
    pub fn resets(&self) -> u64 {
        self.resets
    }

    /// Give the buffer back to itself. Nothing is freed; the cursor moves to the start, and the
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
    /// about to write anyway, and it is the only point both the reset path and a fresh buffer go
    /// through.
    pub fn take(&mut self, len: usize) -> Result<Span, FixedScratchFull> {
        if len > self.remaining() {
            return Err(FixedScratchFull {
                requested: len,
                remaining: self.remaining(),
            });
        }
        let span = Span::new(self.used, self.used + len);
        self.buf[span.start..span.end].fill(0);
        self.used += len;
        Ok(span)
    }

    /// Copy `bytes` in and say where they landed.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Span, FixedScratchFull> {
        let span = self.take(bytes.len())?;
        self.buf[span.start..span.end].copy_from_slice(bytes);
        Ok(span)
    }

    /// Read back what is at a span.
    pub fn read(&self, span: Span) -> &[u8] {
        &self.buf[span.start..span.end.min(FIXED_SCRATCH_BYTES)]
    }

    /// Write into a span this allocator handed out.
    pub fn write(&mut self, span: Span, bytes: &[u8]) -> Result<(), FixedScratchFull> {
        if bytes.len() > span.len() {
            return Err(FixedScratchFull {
                requested: bytes.len(),
                remaining: span.len(),
            });
        }
        self.buf[span.start..span.start + bytes.len()].copy_from_slice(bytes);
        Ok(())
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
///
/// NO derived `Debug` — see the hand-written impl below. `buf` is raw client-credential plaintext
/// (exactly what [`CredentialSlab::mask`] copied out of the cursor); a derived `Debug` would print
/// it verbatim, so any `{:?}` of a containing struct — a log line, a panic message, a trace span —
/// would leak the credential.
pub struct CredentialSlab {
    buf: Vec<u8>,
    cap: usize,
}

/// `Debug` REDACTS `buf` and only `buf` — the same shape as
/// `busbar_plugin::cold::auth::CompleteLoginRequest`'s hand-written impl, so the codebase has ONE
/// redaction idiom rather than two. What survives is the non-secret shape: how many bytes are
/// currently held and the slab's fixed capacity — useful for diagnosing a `CredentialBudget` refusal
/// without ever printing the credential that triggered it.
impl std::fmt::Debug for CredentialSlab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSlab")
            .field("buf", &"[REDACTED]")
            .field("used", &self.buf.len())
            .field("cap", &self.cap)
            .finish()
    }
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
    ///
    /// A bare `Vec::clear()` only drops the LENGTH to zero; the allocation itself is untouched, so
    /// every credential byte this slab ever held keeps sitting in freed-but-not-overwritten heap —
    /// readable by a heap dump, a core file, or a use-after-free/OOB read elsewhere in the process.
    /// `Zeroize::zeroize` overwrites every byte with `0` (via a volatile write the compiler is not
    /// permitted to elide as a dead store, unlike a plain loop-and-assign) before truncating the
    /// length, so "forget everything" is actually true of the memory, not just the `len()`.
    pub fn clear(&mut self) {
        self.buf.zeroize();
    }
}

impl Default for CredentialSlab {
    fn default() -> Self {
        CredentialSlab::new()
    }
}

#[cfg(test)]
#[path = "tests/mask_tests.rs"]
mod tests;
