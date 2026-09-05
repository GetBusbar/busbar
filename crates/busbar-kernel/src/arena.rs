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

use crate::grammar::{ArrivalLocation, MaskKind, Span};

/// The per-unit arena, pinned by the design at 4 KiB.
pub const ARENA_BYTES: usize = 4096;

/// The per-connection cursor cap, which the credential slab is counted inside.
pub const CURSOR_CAP_BYTES: usize = 64 * 1024;

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

    /// Give the arena back to itself. Nothing is zeroed and nothing is freed; the cursor moves to
    /// the start, so the next frame writes over the last one.
    pub fn reset(&mut self) {
        self.used = 0;
        self.resets = self.resets.saturating_add(1);
    }

    /// Take `len` bytes of uninitialised-but-zeroed space, and say where they are.
    pub fn take(&mut self, len: usize) -> Result<Span, ArenaFull> {
        if len > self.remaining() {
            return Err(ArenaFull {
                requested: len,
                remaining: self.remaining(),
            });
        }
        let span = Span::new(self.used, self.used + len);
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
                let max_bytes = match location {
                    ArrivalLocation::HandshakeFrames { max_bytes, .. } => *max_bytes as usize,
                    _ => 0,
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
