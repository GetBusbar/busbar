// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS PLANE'S PIECE ANSWER: what an `on_piece` answer owes the host's reply
//! buffer, and the one settle of the answer's field, unit and arena buffers.
//!
//! `BUSBAR-1.6.0.md` Part 3, section 12, "The route pump": a full reply buffer answers `more = 1`;
//! the kernel flushes it, waits for the caller's side and calls again with the same `from` and zero
//! bytes ([`is_recall`]). An answer that does not fit its field, unit or arena buffer is short as a
//! whole ([`settle`]): the slot answers FAILED, and the kernel re-calls with the same piece and room.
//!
//! The door keeps an [`Owed`] per unit and pays it across the re-calls, so the backpressure rule
//! (`EMIT_DONE` only with the last byte) is written once in this plane. Each plane door carries
//! this logic today; one SDK home for all of them is 1.6.0-QUESTIONS.md PIECE-HOME.

use busbar_contract::abi::plane::{OnPieceIn, OnPieceOut, OutField, UnitCount, EMIT_DONE};
use busbar_contract::abi::sdk::{HostBuf, Lent, Out};

/// Whether `input` is the kernel's re-call after a `more = 1` answer: no bytes, no flags and no
/// attempt.
#[must_use]
pub fn is_recall(input: Lent<'_, OnPieceIn>) -> bool {
    let given = input.get();
    given.flags == 0 && given.attempt_no == 0 && input.field(|i| &i.bytes).bytes().is_empty()
}

/// The bytes a unit's answer still owes the host's reply buffer, and the `EMIT_*` bits they carry.
#[derive(Debug, Default)]
pub struct Owed {
    bytes: Vec<u8>,
    at: usize,
    flags: u32,
}

impl Owed {
    /// Whether any byte is still owed.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.at < self.bytes.len()
    }

    /// Owe `bytes` under the `EMIT_*` `flags`, and pay what fits now. Answers whether the unit is
    /// done: every byte written, with `EMIT_DONE` among `flags`.
    pub fn owe(
        &mut self,
        bytes: &[u8],
        flags: u32,
        input: Lent<'_, OnPieceIn>,
        out: &mut Out<'_, OnPieceOut>,
    ) -> bool {
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
        self.at = 0;
        self.flags = flags;
        self.pay(input, out)
    }

    /// Write what is owed into the reply buffer, as much as fits: `more = 1` while any is left, and
    /// the owed flags on every write, `EMIT_DONE` held back until the last byte. Answers whether the
    /// unit is done.
    pub fn pay(&mut self, input: Lent<'_, OnPieceIn>, out: &mut Out<'_, OnPieceOut>) -> bool {
        let n = input.reply_buf().stream(&self.bytes[self.at..]);
        self.at += n;
        let more = self.pending();
        out.set(|o| &o.emitted, n as u64);
        out.set(|o| &o.more, u32::from(more));
        out.set(
            |o| &o.flags,
            if more {
                self.flags & !EMIT_DONE
            } else {
                self.flags
            },
        );
        if more {
            return false;
        }
        let done = self.flags & EMIT_DONE != 0;
        *self = Owed::default();
        done
    }
}

/// Settle an answer's field, unit and arena buffers: `(written, needed)` of each, short as a whole
/// when any one is short. Answers whether the answer is short.
pub fn settle(
    out: &mut Out<'_, OnPieceOut>,
    fields: &HostBuf<'_, OutField>,
    units: &HostBuf<'_, UnitCount>,
    arena: &HostBuf<'_, u8>,
) -> bool {
    let short = !(fields.fits() && units.fits() && arena.fits());
    let (fw, fnd) = fields.settle(short);
    let (uw, und) = units.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    short
}
