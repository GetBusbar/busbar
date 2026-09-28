// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE ANSWER VALIDATORS (ARCHITECT ruling "answer validators live with the shape",
//! m3-inputs, all kinds). Each is a PURE function over an op's `out`, the capacities the host
//! handed in, and the host's own view of what it handed (the cells, the items). It uses `u64`
//! math, holds no state and dereferences no pointer: a pointer is compared as an address only.
//! The dispatcher calls it after every READY or FAILED answer, and any `Err` makes the answer
//! FAULT. No host re-implements them. Outcomes other than READY and FAILED carry nothing to check.

use super::ledger::{HostRecords, HostSessions, RecordEntry, SessionRow, StreamHead};
use super::money::{
    CellGrant, ReleaseItem, ReserveOut, SliceReleaseOut, UnitCell, RESERVE_NO_CAP,
    RESERVE_NO_FAILED_CELL, RESERVE_OK,
};
use super::{
    HostBlobs, HostBytesOut, HostListOut, LeasedBlobOut, LeasedListOut, LeasedStrListOut,
    VerdictOut, ABSENT, CANCEL_APPLIED, FOUND, VERDICT_YES,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_OCTETS};
use crate::abi::mechanism::lifecycle::CancelOut;
use crate::bounded::MAX_RECORD_BYTES;

/// The hard maximum of any store list's item count (`needed_items`, a leased list's length):
/// 2^20 items, above any list a store answers (the fan-out cap is 10,000 recipients; a scan's
/// `limit` is a `u32` the kernel sizes).
pub const LIST_ITEMS_HARD_MAX: u64 = 1 << 20;
/// The hard maximum of any `needed_bytes` (the ruling: `needed_bytes <= u32::MAX`).
pub const NEEDED_BYTES_HARD_MAX: u64 = u32::MAX as u64;

/// Why an answer is FAULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// A reason, verdict, disposition, `found` or blob format outside the op's vocabulary.
    Vocabulary,
    /// A non-zero `needed_*` with an outcome other than FAILED (M-SB, on
    /// [`OutHead`](crate::abi::mechanism::call::OutHead)).
    NeededNotFailed,
    /// A `needed_bytes` above `u32::MAX`, or a `needed_<count>` above its hard maximum.
    NeededTooLarge,
    /// FAILED with a non-zero `needed_*` that the capacity given already covers (it would waste the
    /// one re-call).
    NeededWithinCap,
    /// FAILED with something written.
    WrittenOnFailed,
    /// A count above its capacity (or its hard maximum).
    CountOverCap,
    /// A count that disagrees with what the op requires (`grants_len != cells_len`, …).
    CountMismatch,
    /// A count above zero with a NULL pointer.
    NullWithCount,
    /// An absent (NULL) item with a non-zero length.
    AbsentWithLen,
    /// An item outside the written part of the host's byte buffer.
    SpanOutOfBounds,
    /// A grant other than the cell's whole `amount`: `0`, partial, or above it (a
    /// cell is granted whole or not at all).
    GrantOutOfRange,
    /// A release above the item's `unspent` (the store clamps; it never returns more).
    ReleaseOverUnspent,
    /// A `failed_cell` that names no cell, or names one on READY.
    FailedCellOutOfRange,
    /// A part the answer requires is absent (a refused cap push's first conflicting index).
    Missing,
}

fn u(n: usize) -> u64 {
    n as u64
}

/// S6: `failed_cell` indexes a cell or is `u32::MAX`, so a reserve holds at most `u32::MAX - 1`
/// cells.
pub fn check_cells_len(cells_len: u64) -> Result<(), Fault> {
    if cells_len > u64::from(u32::MAX - 1) {
        return Err(Fault::CountOverCap);
    }
    Ok(())
}

/// `reserve`'s answer (m3-inputs "store v3 money slots", `reserve`; STORE RULING v2
/// `failed_cell`). `cells` are the cells the host sent, `grants_cap` its array's capacity, and
/// `grants` the first `min(grants_len, grants_cap)` entries of that array.
pub fn check_reserve(
    outcome: Outcome,
    out: &ReserveOut,
    cells: &[UnitCell],
    grants_cap: u64,
    grants: &[CellGrant],
) -> Result<(), Fault> {
    let cells_len = u(cells.len());
    check_cells_len(cells_len)?;
    needed_only_on_failed(outcome, out.needed_grants != 0)?;
    match outcome {
        Outcome::Ready => {
            if out.reason != RESERVE_OK {
                return Err(Fault::Vocabulary);
            }
            if out.failed_cell != RESERVE_NO_FAILED_CELL {
                return Err(Fault::FailedCellOutOfRange);
            }
            if u(out.grants_len) > grants_cap {
                return Err(Fault::CountOverCap);
            }
            if u(out.grants_len) != cells_len || u(grants.len()) != cells_len {
                return Err(Fault::CountMismatch);
            }
            for (cell, grant) in cells.iter().zip(grants) {
                // S5: 1.5.5 is whole-or-nothing, so a READY grant is the cell's whole amount.
                if grant.granted != cell.amount {
                    return Err(Fault::GrantOutOfRange);
                }
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.grants_len != 0 {
                return Err(Fault::WrittenOnFailed);
            }
            if out.needed_grants != 0 {
                // The short-buffer answer (M-SB): no reason, no cell, one grant per cell needed.
                if out.reason != RESERVE_OK {
                    return Err(Fault::Vocabulary);
                }
                if out.failed_cell != RESERVE_NO_FAILED_CELL {
                    return Err(Fault::FailedCellOutOfRange);
                }
                short(out.needed_grants, grants_cap, u64::from(u32::MAX - 1))?;
                if out.needed_grants != cells_len {
                    return Err(Fault::CountMismatch);
                }
                return Ok(());
            }
            if out.reason == RESERVE_OK || out.reason > RESERVE_NO_CAP {
                return Err(Fault::Vocabulary);
            }
            if out.failed_cell != RESERVE_NO_FAILED_CELL && u64::from(out.failed_cell) >= cells_len
            {
                return Err(Fault::FailedCellOutOfRange);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `slice_release`'s answer (m3-inputs "store v3 money slots", `slice_release`: clamped, never
/// more than granted). `items` are the items the host sent, `released_cap` its array's capacity,
/// and `released` the first `min(released_len, released_cap)` entries of that array.
pub fn check_slice_release(
    outcome: Outcome,
    out: &SliceReleaseOut,
    items: &[ReleaseItem],
    released_cap: u64,
    released: &[u64],
) -> Result<(), Fault> {
    needed_only_on_failed(outcome, out.needed_released != 0)?;
    match outcome {
        Outcome::Ready => {
            if u(out.released_len) > released_cap {
                return Err(Fault::CountOverCap);
            }
            if u(out.released_len) != u(items.len()) || released.len() != items.len() {
                return Err(Fault::CountMismatch);
            }
            if items.iter().zip(released).any(|(i, r)| *r > i.unspent) {
                return Err(Fault::ReleaseOverUnspent);
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.released_len != 0 {
                return Err(Fault::WrittenOnFailed);
            }
            if out.needed_released != 0 {
                short(out.needed_released, released_cap, LIST_ITEMS_HARD_MAX)?;
                if out.needed_released != u(items.len()) {
                    return Err(Fault::CountMismatch);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// M-SB: a non-zero `needed_*` with any outcome other than FAILED is FAULT.
fn needed_only_on_failed(outcome: Outcome, any_needed: bool) -> Result<(), Fault> {
    if any_needed && outcome != Outcome::Failed {
        return Err(Fault::NeededNotFailed);
    }
    Ok(())
}

/// `window_caps`' answer (m3-inputs "window caps" correction (1)): the push is atomic, so READY
/// and FAILED carry nothing to check; a REFUSED push names the first conflicting cap. `caps_len`
/// is how many caps the host pushed, and `error` the bytes of `out.error` as the host copied them
/// (`None` when the plugin left it absent). A REFUSED `error` must BEGIN with the decimal index of
/// a cap in the push.
pub fn check_window_caps(
    outcome: Outcome,
    caps_len: u64,
    error: Option<&[u8]>,
) -> Result<(), Fault> {
    if caps_len > LIST_ITEMS_HARD_MAX {
        return Err(Fault::CountOverCap);
    }
    if outcome != Outcome::Refused {
        return Ok(());
    }
    let text = error.ok_or(Fault::Missing)?;
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || digits > 10 {
        return Err(Fault::Missing);
    }
    let index = text[..digits]
        .iter()
        .fold(0u64, |n, d| n * 10 + u64::from(d - b'0'));
    if index >= caps_len {
        return Err(Fault::CountOverCap);
    }
    Ok(())
}

/// A short FAILED's `needed_*`: within the hard maxima, and `0` or above the capacity given.
fn short(needed: u64, cap: u64, hard: u64) -> Result<(), Fault> {
    if needed > hard {
        return Err(Fault::NeededTooLarge);
    }
    if needed != 0 && needed <= cap {
        return Err(Fault::NeededWithinCap);
    }
    Ok(())
}

/// A single-value read into a host buffer of `cap` bytes, whose value is at most `hard` bytes.
fn check_bytes(outcome: Outcome, out: &HostBytesOut, cap: u64, hard: u64) -> Result<(), Fault> {
    if out.found != FOUND && out.found != ABSENT {
        return Err(Fault::Vocabulary);
    }
    needed_only_on_failed(outcome, out.needed != 0)?;
    match outcome {
        Outcome::Ready => {
            if out.written > cap || out.written > hard {
                return Err(Fault::CountOverCap);
            }
            if out.found == ABSENT && out.written != 0 {
                return Err(Fault::AbsentWithLen);
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.written != 0 {
                return Err(Fault::WrittenOnFailed);
            }
            short(out.needed, cap, hard.min(NEEDED_BYTES_HARD_MAX))
        }
        _ => Ok(()),
    }
}

/// `record_get`'s answer: a value of at most `MAX_RECORD_BYTES` into the host buffer of `cap`.
pub fn check_record_get(outcome: Outcome, out: &HostBytesOut, cap: u64) -> Result<(), Fault> {
    check_bytes(outcome, out, cap, u(MAX_RECORD_BYTES))
}

/// `get_plane_record`'s answer: an opaque body into the host buffer of `cap`.
pub fn check_get_plane_record(outcome: Outcome, out: &HostBytesOut, cap: u64) -> Result<(), Fault> {
    check_bytes(outcome, out, cap, NEEDED_BYTES_HARD_MAX)
}

/// The host buffers a list was written into, as addresses and capacities.
#[derive(Debug, Clone, Copy)]
struct ListBufs {
    items_null: bool,
    items_cap: u64,
    bytes_base: u64,
    bytes_cap: u64,
}

/// One written item's bytes, `(address, len)`; address `0` = absent.
fn span_in(ptr: usize, len: u64, bufs: ListBufs, written: u64) -> Result<(), Fault> {
    if ptr == 0 {
        return if len == 0 {
            Ok(())
        } else {
            Err(Fault::AbsentWithLen)
        };
    }
    let start = u(ptr);
    let end = start.checked_add(len).ok_or(Fault::SpanOutOfBounds)?;
    let limit = bufs
        .bytes_base
        .checked_add(written)
        .ok_or(Fault::SpanOutOfBounds)?;
    if start < bufs.bytes_base || end > limit {
        return Err(Fault::SpanOutOfBounds);
    }
    Ok(())
}

/// A request-path list's counts, then each item's spans (`spans` yields `(address, len)`).
fn check_list(
    outcome: Outcome,
    out: &HostListOut,
    bufs: ListBufs,
    items_len: usize,
    spans: impl Iterator<Item = (usize, u64)>,
) -> Result<(), Fault> {
    needed_only_on_failed(outcome, out.needed_items != 0 || out.needed_bytes != 0)?;
    match outcome {
        Outcome::Ready => {
            if out.items_written > bufs.items_cap || out.bytes_written > bufs.bytes_cap {
                return Err(Fault::CountOverCap);
            }
            if out.items_written != u(items_len) {
                return Err(Fault::CountMismatch);
            }
            if (out.items_written > 0 && bufs.items_null)
                || (out.bytes_written > 0 && bufs.bytes_base == 0)
            {
                return Err(Fault::NullWithCount);
            }
            for (ptr, len) in spans {
                span_in(ptr, len, bufs, out.bytes_written)?;
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.items_written != 0 || out.bytes_written != 0 {
                return Err(Fault::WrittenOnFailed);
            }
            // M-SB REFINEMENT (multi-dimension): every `needed_*` is that dimension's FULL size,
            // so a dimension that fits reports a size `<=` its cap; the answer is short only if
            // AT LEAST ONE dimension is over its cap.
            if out.needed_items > LIST_ITEMS_HARD_MAX || out.needed_bytes > NEEDED_BYTES_HARD_MAX {
                return Err(Fault::NeededTooLarge);
            }
            if (out.needed_items != 0 || out.needed_bytes != 0)
                && out.needed_items <= bufs.items_cap
                && out.needed_bytes <= bufs.bytes_cap
            {
                return Err(Fault::NeededWithinCap);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn blob_fmt(b: &Blob) -> Result<(), Fault> {
    if b.fmt > BLOB_OCTETS {
        return Err(Fault::Vocabulary);
    }
    Ok(())
}

/// `list_plane_records`' answer. `host` is the [`HostBlobs`] the host handed in, `items` the first
/// `min(items_written, items_cap)` blobs of its array.
pub fn check_list_plane_records(
    outcome: Outcome,
    out: &HostListOut,
    host: &HostBlobs,
    items: &[Blob],
) -> Result<(), Fault> {
    let bufs = ListBufs {
        items_null: host.items.is_null(),
        items_cap: u(host.items_cap),
        bytes_base: host.bytes.ptr as usize as u64,
        bytes_cap: u(host.bytes.cap),
    };
    if outcome == Outcome::Ready {
        items.iter().try_for_each(blob_fmt)?;
    }
    let spans = items.iter().map(|b| (b.ptr as usize, u(b.len)));
    check_list(outcome, out, bufs, items.len(), spans)
}

/// `sessions_for`'s answer. `host` is the [`HostSessions`] the host handed in, `rows` the first
/// `min(items_written, items_cap)` rows of its array.
pub fn check_sessions_for(
    outcome: Outcome,
    out: &HostListOut,
    host: &HostSessions,
    rows: &[SessionRow],
) -> Result<(), Fault> {
    let bufs = ListBufs {
        items_null: host.items.is_null(),
        items_cap: u(host.items_cap),
        bytes_base: host.bytes.ptr as usize as u64,
        bytes_cap: u(host.bytes.cap),
    };
    let spans = rows.iter().map(|r| (r.node.ptr as usize, u(r.node.len)));
    check_list(outcome, out, bufs, rows.len(), spans)
}

/// `record_scan`'s answer. `host` is the [`HostRecords`] the host handed in, `entries` the first
/// `min(items_written, items_cap)` entries of its array, `limit` the scan's own limit (READY with
/// more than `limit` entries is FAULT; `limit` 0 means nothing).
pub fn check_record_scan(
    outcome: Outcome,
    out: &HostListOut,
    host: &HostRecords,
    entries: &[RecordEntry],
    limit: u32,
) -> Result<(), Fault> {
    let bufs = ListBufs {
        items_null: host.items.is_null(),
        items_cap: u(host.items_cap),
        bytes_base: host.bytes.ptr as usize as u64,
        bytes_cap: u(host.bytes.cap),
    };
    if outcome == Outcome::Ready {
        if out.items_written > u64::from(limit) {
            return Err(Fault::CountOverCap);
        }
        for e in entries {
            blob_fmt(&e.key)?;
            blob_fmt(&e.value)?;
            if u(e.value.len) > u(MAX_RECORD_BYTES) {
                return Err(Fault::CountOverCap);
            }
        }
    }
    let spans = entries.iter().flat_map(|e| {
        [
            (e.key.ptr as usize, u(e.key.len)),
            (e.value.ptr as usize, u(e.value.len)),
        ]
    });
    check_list(outcome, out, bufs, entries.len(), spans)
}

/// A plugin-owned item: NULL only with length `0`.
fn owned(ptr_null: bool, len: usize) -> Result<(), Fault> {
    if ptr_null && len != 0 {
        return Err(Fault::NullWithCount);
    }
    Ok(())
}

/// A leased list's own count and array.
fn leased_count(null: bool, len: usize, seen: usize) -> Result<(), Fault> {
    if u(len) > LIST_ITEMS_HARD_MAX {
        return Err(Fault::CountOverCap);
    }
    if len > 0 && null {
        return Err(Fault::NullWithCount);
    }
    if seen != len {
        return Err(Fault::CountMismatch);
    }
    Ok(())
}

/// An off-path single record under a lease (`get_key`, `get_usage`, `lookup_credential_secret`).
pub fn check_leased_blob(outcome: Outcome, out: &LeasedBlobOut) -> Result<(), Fault> {
    if outcome != Outcome::Ready {
        return Ok(());
    }
    match out.found {
        ABSENT if out.record.len != 0 || !out.record.ptr.is_null() => Err(Fault::AbsentWithLen),
        ABSENT => Ok(()),
        FOUND => {
            blob_fmt(&out.record)?;
            owned(out.record.ptr.is_null(), out.record.len)
        }
        _ => Err(Fault::Vocabulary),
    }
}

/// An off-path list of records under a lease. `items` is `out.items[..out.items_len]` as the host
/// read it after the count checks.
pub fn check_leased_list(
    outcome: Outcome,
    out: &LeasedListOut,
    items: &[Blob],
) -> Result<(), Fault> {
    if outcome != Outcome::Ready {
        return Ok(());
    }
    leased_count(out.items.is_null(), out.items_len, items.len())?;
    items.iter().try_for_each(|b| {
        blob_fmt(b)?;
        owned(b.ptr.is_null(), b.len)
    })
}

/// An off-path list of strings under a lease (`list_denylist`, `list_plane_record_parents`).
pub fn check_leased_strs(
    outcome: Outcome,
    out: &LeasedStrListOut,
    items: &[AbiStr],
) -> Result<(), Fault> {
    if outcome != Outcome::Ready {
        return Ok(());
    }
    leased_count(out.items.is_null(), out.items_len, items.len())?;
    items.iter().try_for_each(|s| owned(s.ptr.is_null(), s.len))
}

/// `heads`' answer under a lease.
pub fn check_heads(
    outcome: Outcome,
    out: &super::ledger::HeadsOut,
    items: &[StreamHead],
) -> Result<(), Fault> {
    if outcome != Outcome::Ready {
        return Ok(());
    }
    leased_count(out.items.is_null(), out.items_len, items.len())?;
    items
        .iter()
        .try_for_each(|h| owned(h.stream.ptr.is_null(), h.stream.len))
}

/// `redeem_plane_token`'s and `plane_token_live`'s answer: YES or NO only.
pub fn check_verdict(outcome: Outcome, out: &VerdictOut) -> Result<(), Fault> {
    if outcome == Outcome::Ready && out.verdict > VERDICT_YES {
        return Err(Fault::Vocabulary);
    }
    Ok(())
}

/// `cancel`'s answer: a store disposition only (0 UNKNOWN, 1 NOT_APPLIED, 2 APPLIED).
pub fn check_cancel(outcome: Outcome, out: &CancelOut) -> Result<(), Fault> {
    if outcome == Outcome::Ready && out.disposition > CANCEL_APPLIED {
        return Err(Fault::Vocabulary);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/check_tests.rs"]
mod tests;
