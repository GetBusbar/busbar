// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE ANSWER VALIDATORS: answer validators live with the shape, for every kind. Each is a PURE function over an op's `out`, the capacities the host
//! handed in, and the host's own view of what it handed (the cells, the items). It uses `u64`
//! math, holds no state and dereferences no pointer: a pointer is compared as an address only.
//! The dispatcher calls it on every answer, whatever its outcome, and any `Err` makes the answer
//! FAULT. No host re-implements them.
//!
//! Each validator decides per outcome which fields matter. The host zeroes the `out` before every
//! call, so a PENDING or REFUSED answer that states nothing beyond its head passes; the only rules
//! that bind those outcomes are about them: a `needed_*` on anything but FAILED, and a REFUSED
//! `window_caps` push naming its first conflicting cap.

use super::ledger::HeadOut;
use super::ledger::{HostRecords, HostSessions, RecordEntry, SessionRow, StreamHead};
use super::money::{
    CellGrant, ReleaseItem, ReserveOut, SliceReleaseOut, UnitCell, RESERVE_NO_CAP,
    RESERVE_NO_FAILED_CELL, RESERVE_OK,
};
use super::{
    CountOut, HostBlobs, HostBytesOut, HostListOut, LeasedBlobOut, LeasedListOut, LeasedStrListOut,
    VerdictOut, ABSENT, CANCEL_APPLIED, FOUND, VERDICT_YES,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_OCTETS};
use crate::abi::mechanism::check::{fault, Rule};
use crate::abi::mechanism::lifecycle::CancelOut;
use crate::bounded::MAX_RECORD_BYTES;

pub use crate::abi::mechanism::check::Fault;

/// The hard maximum of any store list's item count (`needed_items`, a leased list's length):
/// 2^20 items, above any list a store answers (the fan-out cap is 10,000 recipients; a scan's
/// `limit` is a `u32` the kernel sizes).
pub const LIST_ITEMS_HARD_MAX: u64 = 1 << 20;
/// The hard maximum of any `needed_bytes` (`needed_bytes <= u32::MAX`).
pub const NEEDED_BYTES_HARD_MAX: u64 = u32::MAX as u64;

// WHY AN ANSWER IS FAULT: the shared `Fault`, one `Rule` and one distinct `store.<op>.<arm>` field per arm
// (the design: every answer validator gives a distinct message per arm). `ALL` lists every one so a test can hold them distinct.
/// A reserve of more cells than `failed_cell` can index (S6).
pub const RESERVE_CELLS_OVER_MAX: Fault = fault(Rule::OverCap, "store.reserve.cells_over_max");
/// A READY reserve that states a reason.
pub const RESERVE_READY_REASON: Fault = fault(Rule::UnknownCode, "store.reserve.ready_reason");
/// A READY reserve that names a failed cell.
pub const RESERVE_READY_FAILED_CELL: Fault =
    fault(Rule::IndexOutOfRange, "store.reserve.ready_failed_cell");
/// A READY reserve with `grants_len` above the grants capacity.
pub const RESERVE_GRANTS_OVER_CAP: Fault = fault(Rule::OverCap, "store.reserve.grants_over_cap");
/// A READY reserve without exactly one grant per cell.
pub const RESERVE_GRANTS_MISMATCH: Fault =
    fault(Rule::Contradiction, "store.reserve.grants_mismatch");
/// A READY grant other than the cell's whole `amount`: `0`, partial, or above it (a cell is granted whole or not at all).
pub const RESERVE_GRANT_NOT_WHOLE: Fault =
    fault(Rule::Contradiction, "store.reserve.grant_not_whole");
/// A FAILED reserve that wrote grants.
pub const RESERVE_FAILED_GRANTS_WRITTEN: Fault =
    fault(Rule::WrittenOnShort, "store.reserve.failed_grants_written");
/// A short-buffer reserve answer that states a reason.
pub const RESERVE_SHORT_REASON: Fault = fault(Rule::UnknownCode, "store.reserve.short_reason");
/// A short-buffer reserve answer that names a failed cell.
pub const RESERVE_SHORT_FAILED_CELL: Fault =
    fault(Rule::IndexOutOfRange, "store.reserve.short_failed_cell");
/// A reserve `needed_grants` above the most cells a reserve holds.
pub const RESERVE_NEEDED_TOO_LARGE: Fault = fault(Rule::OverMax, "store.reserve.needed_too_large");
/// A reserve `needed_grants` the grants capacity already covers.
pub const RESERVE_NEEDED_WITHIN_CAP: Fault =
    fault(Rule::WastedRecall, "store.reserve.needed_within_cap");
/// A short-buffer reserve answer needing other than one grant per cell.
pub const RESERVE_NEEDED_MISMATCH: Fault =
    fault(Rule::Contradiction, "store.reserve.needed_mismatch");
/// A FAILED reserve whose reason is `OK` or past the vocabulary.
pub const RESERVE_FAILED_REASON: Fault = fault(Rule::UnknownCode, "store.reserve.failed_reason");
/// A FAILED reserve whose `failed_cell` names no cell.
pub const RESERVE_FAILED_CELL: Fault = fault(Rule::IndexOutOfRange, "store.reserve.failed_cell");
/// A READY slice release with `released_len` above the capacity.
pub const SLICE_RELEASED_OVER_CAP: Fault =
    fault(Rule::OverCap, "store.slice_release.released_over_cap");
/// A READY slice release without exactly one amount per item.
pub const SLICE_RELEASED_MISMATCH: Fault =
    fault(Rule::Contradiction, "store.slice_release.released_mismatch");
/// A release above the item's `unspent` (the store clamps; it never returns more).
pub const SLICE_RELEASE_OVER_UNSPENT: Fault = fault(
    Rule::Contradiction,
    "store.slice_release.release_over_unspent",
);
/// A FAILED slice release that wrote amounts.
pub const SLICE_FAILED_WRITTEN: Fault =
    fault(Rule::WrittenOnShort, "store.slice_release.failed_written");
/// A slice release `needed_released` above the list maximum.
pub const SLICE_NEEDED_TOO_LARGE: Fault =
    fault(Rule::OverMax, "store.slice_release.needed_too_large");
/// A slice release `needed_released` the capacity already covers.
pub const SLICE_NEEDED_WITHIN_CAP: Fault =
    fault(Rule::WastedRecall, "store.slice_release.needed_within_cap");
/// A short slice release needing other than one amount per item.
pub const SLICE_NEEDED_MISMATCH: Fault =
    fault(Rule::Contradiction, "store.slice_release.needed_mismatch");
/// A non-zero `needed_*` with an outcome other than FAILED (M-SB, on [`OutHead`](crate::abi::mechanism::call::OutHead)). Every op shares this one arm: it is one check.
pub const NEEDED_NOT_FAILED: Fault = fault(Rule::NeededNotFailed, "store.needed_not_failed");
/// A `window_caps` push of more caps than the list maximum.
pub const WINDOW_CAPS_OVER_MAX: Fault = fault(Rule::OverCap, "store.window_caps.caps_over_max");
/// A REFUSED `window_caps` with no `error` text.
pub const WINDOW_ERROR_MISSING: Fault = fault(Rule::Missing, "store.window_caps.error_missing");
/// A REFUSED `window_caps` whose `error` does not begin with a cap index.
pub const WINDOW_ERROR_INDEX_MISSING: Fault =
    fault(Rule::Missing, "store.window_caps.error_index_missing");
/// A REFUSED `window_caps` naming a cap index outside the push.
pub const WINDOW_ERROR_INDEX_OVER: Fault =
    fault(Rule::OverCap, "store.window_caps.error_index_over");
/// A single-value read whose `found` is neither FOUND nor ABSENT.
pub const BYTES_FOUND: Fault = fault(Rule::UnknownCode, "store.bytes.found");
/// A single-value read that wrote above the capacity or the value ceiling.
pub const BYTES_WRITTEN_OVER_CAP: Fault = fault(Rule::OverCap, "store.bytes.written_over_cap");
/// An ABSENT single-value read that wrote bytes.
pub const BYTES_ABSENT_WRITTEN: Fault = fault(Rule::SpanNotAbsent, "store.bytes.absent_written");
/// A FAILED single-value read that wrote bytes.
pub const BYTES_FAILED_WRITTEN: Fault = fault(Rule::WrittenOnShort, "store.bytes.failed_written");
/// A single-value read `needed` above its hard maximum.
pub const BYTES_NEEDED_TOO_LARGE: Fault = fault(Rule::OverMax, "store.bytes.needed_too_large");
/// A single-value read `needed` the capacity already covers.
pub const BYTES_NEEDED_WITHIN_CAP: Fault =
    fault(Rule::WastedRecall, "store.bytes.needed_within_cap");
/// A list that wrote more items or bytes than its capacities.
pub const LIST_WRITTEN_OVER_CAP: Fault = fault(Rule::OverCap, "store.list.written_over_cap");
/// A list whose `items_written` disagrees with the items the host read.
pub const LIST_ITEMS_MISMATCH: Fault = fault(Rule::Contradiction, "store.list.items_mismatch");
/// A list that wrote items or bytes into a NULL buffer.
pub const LIST_NULL_WITH_COUNT: Fault = fault(Rule::NullWithCount, "store.list.null_with_count");
/// A FAILED list that wrote items or bytes.
pub const LIST_FAILED_WRITTEN: Fault = fault(Rule::WrittenOnShort, "store.list.failed_written");
/// A list `needed_items` or `needed_bytes` above its hard maximum.
pub const LIST_NEEDED_TOO_LARGE: Fault = fault(Rule::OverMax, "store.list.needed_too_large");
/// A short list in which every dimension already fits its capacity.
pub const LIST_NEEDED_WITHIN_CAP: Fault = fault(Rule::WastedRecall, "store.list.needed_within_cap");
/// An absent (NULL) list item with a non-zero length.
pub const SPAN_ABSENT_WITH_LEN: Fault = fault(Rule::SpanNotAbsent, "store.span.absent_with_len");
/// A list item whose address plus length overflows.
pub const SPAN_END_OVERFLOW: Fault = fault(Rule::SpanOutOfBounds, "store.span.end_overflow");
/// A list whose byte buffer base plus bytes written overflows.
pub const SPAN_LIMIT_OVERFLOW: Fault = fault(Rule::SpanOutOfBounds, "store.span.limit_overflow");
/// A list item outside the written part of the host's byte buffer.
pub const SPAN_OUT_OF_BOUNDS: Fault = fault(Rule::SpanOutOfBounds, "store.span.out_of_bounds");
/// A blob format outside the vocabulary.
pub const BLOB_FMT: Fault = fault(Rule::UnknownCode, "store.blob.fmt");
/// A `record_scan` that returned more entries than its `limit`.
pub const SCAN_OVER_LIMIT: Fault = fault(Rule::OverCap, "store.record_scan.over_limit");
/// A `record_scan` value above the record ceiling.
pub const SCAN_VALUE_OVER_MAX: Fault = fault(Rule::OverCap, "store.record_scan.value_over_max");
/// A plugin-owned item that is NULL with a non-zero length.
pub const OWNED_NULL_WITH_LEN: Fault = fault(Rule::NullWithCount, "store.owned.null_with_len");
/// A leased list longer than the list maximum.
pub const LEASED_ITEMS_OVER_MAX: Fault = fault(Rule::OverCap, "store.leased.items_over_max");
/// A leased list with a count above zero and a NULL array.
pub const LEASED_NULL_WITH_COUNT: Fault =
    fault(Rule::NullWithCount, "store.leased.null_with_count");
/// A leased list whose count disagrees with the items the host read.
pub const LEASED_ITEMS_MISMATCH: Fault = fault(Rule::Contradiction, "store.leased.items_mismatch");
/// An ABSENT leased blob that carries a record.
pub const LEASED_BLOB_ABSENT_WITH_RECORD: Fault =
    fault(Rule::SpanNotAbsent, "store.leased_blob.absent_with_record");
/// A leased blob whose `found` is neither FOUND nor ABSENT.
pub const LEASED_BLOB_FOUND: Fault = fault(Rule::UnknownCode, "store.leased_blob.found");
/// A verdict past YES.
pub const VERDICT_VOCABULARY: Fault = fault(Rule::UnknownCode, "store.verdict.verdict");
/// A FAILED purge that states a removed count.
pub const COUNT_FAILED_WRITTEN: Fault = fault(Rule::WrittenOnShort, "store.count.failed_written");
/// A FAILED `append_batch` that states a stream head.
pub const APPEND_FAILED_HEAD: Fault = fault(Rule::WrittenOnShort, "store.append_batch.failed_head");
/// A `cancel` disposition past APPLIED.
pub const CANCEL_DISPOSITION: Fault = fault(Rule::UnknownCode, "store.cancel.disposition");

/// Every fault this module can answer with.
pub const ALL: &[Fault] = &[
    RESERVE_CELLS_OVER_MAX,
    RESERVE_READY_REASON,
    RESERVE_READY_FAILED_CELL,
    RESERVE_GRANTS_OVER_CAP,
    RESERVE_GRANTS_MISMATCH,
    RESERVE_GRANT_NOT_WHOLE,
    RESERVE_FAILED_GRANTS_WRITTEN,
    RESERVE_SHORT_REASON,
    RESERVE_SHORT_FAILED_CELL,
    RESERVE_NEEDED_TOO_LARGE,
    RESERVE_NEEDED_WITHIN_CAP,
    RESERVE_NEEDED_MISMATCH,
    RESERVE_FAILED_REASON,
    RESERVE_FAILED_CELL,
    SLICE_RELEASED_OVER_CAP,
    SLICE_RELEASED_MISMATCH,
    SLICE_RELEASE_OVER_UNSPENT,
    SLICE_FAILED_WRITTEN,
    SLICE_NEEDED_TOO_LARGE,
    SLICE_NEEDED_WITHIN_CAP,
    SLICE_NEEDED_MISMATCH,
    NEEDED_NOT_FAILED,
    WINDOW_CAPS_OVER_MAX,
    WINDOW_ERROR_MISSING,
    WINDOW_ERROR_INDEX_MISSING,
    WINDOW_ERROR_INDEX_OVER,
    BYTES_FOUND,
    BYTES_WRITTEN_OVER_CAP,
    BYTES_ABSENT_WRITTEN,
    BYTES_FAILED_WRITTEN,
    BYTES_NEEDED_TOO_LARGE,
    BYTES_NEEDED_WITHIN_CAP,
    LIST_WRITTEN_OVER_CAP,
    LIST_ITEMS_MISMATCH,
    LIST_NULL_WITH_COUNT,
    LIST_FAILED_WRITTEN,
    LIST_NEEDED_TOO_LARGE,
    LIST_NEEDED_WITHIN_CAP,
    SPAN_ABSENT_WITH_LEN,
    SPAN_END_OVERFLOW,
    SPAN_LIMIT_OVERFLOW,
    SPAN_OUT_OF_BOUNDS,
    BLOB_FMT,
    SCAN_OVER_LIMIT,
    SCAN_VALUE_OVER_MAX,
    OWNED_NULL_WITH_LEN,
    LEASED_ITEMS_OVER_MAX,
    LEASED_NULL_WITH_COUNT,
    LEASED_ITEMS_MISMATCH,
    LEASED_BLOB_ABSENT_WITH_RECORD,
    LEASED_BLOB_FOUND,
    VERDICT_VOCABULARY,
    COUNT_FAILED_WRITTEN,
    APPEND_FAILED_HEAD,
    CANCEL_DISPOSITION,
];

fn u(n: usize) -> u64 {
    n as u64
}

/// S6: `failed_cell` indexes a cell or is `u32::MAX`, so a reserve holds at most `u32::MAX - 1`
/// cells.
pub fn check_cells_len(cells_len: u64) -> Result<(), Fault> {
    if cells_len > u64::from(u32::MAX - 1) {
        return Err(RESERVE_CELLS_OVER_MAX);
    }
    Ok(())
}

/// `reserve`'s answer: whole grants on READY, a reason and an optional `failed_cell` on FAILED,
/// or the short-buffer answer. `cells` are the cells the host sent, `grants_cap` its array's capacity, and
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
                return Err(RESERVE_READY_REASON);
            }
            if out.failed_cell != RESERVE_NO_FAILED_CELL {
                return Err(RESERVE_READY_FAILED_CELL);
            }
            if u(out.grants_len) > grants_cap {
                return Err(RESERVE_GRANTS_OVER_CAP);
            }
            if u(out.grants_len) != cells_len || u(grants.len()) != cells_len {
                return Err(RESERVE_GRANTS_MISMATCH);
            }
            for (cell, grant) in cells.iter().zip(grants) {
                // S5: 1.5.5 is whole-or-nothing, so a READY grant is the cell's whole amount.
                if grant.granted != cell.amount {
                    return Err(RESERVE_GRANT_NOT_WHOLE);
                }
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.grants_len != 0 {
                return Err(RESERVE_FAILED_GRANTS_WRITTEN);
            }
            if out.needed_grants != 0 {
                // The short-buffer answer (M-SB): no reason, no cell, one grant per cell needed.
                if out.reason != RESERVE_OK {
                    return Err(RESERVE_SHORT_REASON);
                }
                if out.failed_cell != RESERVE_NO_FAILED_CELL {
                    return Err(RESERVE_SHORT_FAILED_CELL);
                }
                short(
                    out.needed_grants,
                    grants_cap,
                    u64::from(u32::MAX - 1),
                    (RESERVE_NEEDED_TOO_LARGE, RESERVE_NEEDED_WITHIN_CAP),
                )?;
                if out.needed_grants != cells_len {
                    return Err(RESERVE_NEEDED_MISMATCH);
                }
                return Ok(());
            }
            if out.reason == RESERVE_OK || out.reason > RESERVE_NO_CAP {
                return Err(RESERVE_FAILED_REASON);
            }
            if out.failed_cell != RESERVE_NO_FAILED_CELL && u64::from(out.failed_cell) >= cells_len
            {
                return Err(RESERVE_FAILED_CELL);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `slice_release`'s answer: clamped, never more than granted. `items` are the items the host sent, `released_cap` its array's capacity,
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
                return Err(SLICE_RELEASED_OVER_CAP);
            }
            if u(out.released_len) != u(items.len()) || released.len() != items.len() {
                return Err(SLICE_RELEASED_MISMATCH);
            }
            if items.iter().zip(released).any(|(i, r)| *r > i.unspent) {
                return Err(SLICE_RELEASE_OVER_UNSPENT);
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.released_len != 0 {
                return Err(SLICE_FAILED_WRITTEN);
            }
            if out.needed_released != 0 {
                short(
                    out.needed_released,
                    released_cap,
                    LIST_ITEMS_HARD_MAX,
                    (SLICE_NEEDED_TOO_LARGE, SLICE_NEEDED_WITHIN_CAP),
                )?;
                if out.needed_released != u(items.len()) {
                    return Err(SLICE_NEEDED_MISMATCH);
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
        return Err(NEEDED_NOT_FAILED);
    }
    Ok(())
}

/// `window_caps`' answer: the push is atomic, so READY and FAILED carry nothing beyond the count
/// check; a REFUSED push names the first conflicting cap. `caps_len`
/// is how many caps the host pushed, and `error` the bytes of `out.error` as the host copied them
/// (`None` when the plugin left it absent). A REFUSED `error` must BEGIN with the decimal index of
/// a cap in the push, or with [`super::DIAG_OPID_CONFLICT`] (the push's `op_id` was used before).
pub fn check_window_caps(
    outcome: Outcome,
    caps_len: u64,
    error: Option<&[u8]>,
) -> Result<(), Fault> {
    if caps_len > LIST_ITEMS_HARD_MAX {
        return Err(WINDOW_CAPS_OVER_MAX);
    }
    if outcome != Outcome::Refused {
        return Ok(());
    }
    let text = error.ok_or(WINDOW_ERROR_MISSING)?;
    // An `op_id` replayed with a different push is REFUSED as every store op's is (DEDUPE): its
    // text names the conflict, not a cap.
    if text.starts_with(super::DIAG_OPID_CONFLICT.as_bytes()) {
        return Ok(());
    }
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || digits > 10 {
        return Err(WINDOW_ERROR_INDEX_MISSING);
    }
    let index = text[..digits]
        .iter()
        .fold(0u64, |n, d| n * 10 + u64::from(d - b'0'));
    if index >= caps_len {
        return Err(WINDOW_ERROR_INDEX_OVER);
    }
    Ok(())
}

/// A short FAILED's `needed_*`: within the hard maxima, and `0` or above the capacity given. `faults` is
/// the caller's own `(too large, within capacity)` pair.
/// NOT `mechanism::check::result`: a store FAILED writes nothing even when not short, which the
/// shared rule allows, and that stricter rule guards `reserve`/`slice_release` (ARCHITECT 2026-09-30).
fn short(needed: u64, cap: u64, hard: u64, faults: (Fault, Fault)) -> Result<(), Fault> {
    let (too_large, within_cap) = faults;
    if needed > hard {
        return Err(too_large);
    }
    if needed != 0 && needed <= cap {
        return Err(within_cap);
    }
    Ok(())
}

/// A single-value read into a host buffer of `cap` bytes, whose value is at most `hard` bytes.
/// `found` and `written` are read on READY only; `needed` binds every outcome (M-SB).
fn check_bytes(outcome: Outcome, out: &HostBytesOut, cap: u64, hard: u64) -> Result<(), Fault> {
    needed_only_on_failed(outcome, out.needed != 0)?;
    match outcome {
        Outcome::Ready => {
            if out.found != FOUND && out.found != ABSENT {
                return Err(BYTES_FOUND);
            }
            if out.written > cap || out.written > hard {
                return Err(BYTES_WRITTEN_OVER_CAP);
            }
            if out.found == ABSENT && out.written != 0 {
                return Err(BYTES_ABSENT_WRITTEN);
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.written != 0 {
                return Err(BYTES_FAILED_WRITTEN);
            }
            short(
                out.needed,
                cap,
                hard.min(NEEDED_BYTES_HARD_MAX),
                (BYTES_NEEDED_TOO_LARGE, BYTES_NEEDED_WITHIN_CAP),
            )
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
            Err(SPAN_ABSENT_WITH_LEN)
        };
    }
    let start = u(ptr);
    let end = start.checked_add(len).ok_or(SPAN_END_OVERFLOW)?;
    let limit = bufs
        .bytes_base
        .checked_add(written)
        .ok_or(SPAN_LIMIT_OVERFLOW)?;
    if start < bufs.bytes_base || end > limit {
        return Err(SPAN_OUT_OF_BOUNDS);
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
                return Err(LIST_WRITTEN_OVER_CAP);
            }
            if out.items_written != u(items_len) {
                return Err(LIST_ITEMS_MISMATCH);
            }
            if (out.items_written > 0 && bufs.items_null)
                || (out.bytes_written > 0 && bufs.bytes_base == 0)
            {
                return Err(LIST_NULL_WITH_COUNT);
            }
            for (ptr, len) in spans {
                span_in(ptr, len, bufs, out.bytes_written)?;
            }
            Ok(())
        }
        Outcome::Failed => {
            if out.items_written != 0 || out.bytes_written != 0 {
                return Err(LIST_FAILED_WRITTEN);
            }
            // M-SB REFINEMENT (multi-dimension): every `needed_*` is that dimension's FULL size,
            // so a dimension that fits reports a size `<=` its cap; the answer is short only if
            // AT LEAST ONE dimension is over its cap.
            if out.needed_items > LIST_ITEMS_HARD_MAX || out.needed_bytes > NEEDED_BYTES_HARD_MAX {
                return Err(LIST_NEEDED_TOO_LARGE);
            }
            if (out.needed_items != 0 || out.needed_bytes != 0)
                && out.needed_items <= bufs.items_cap
                && out.needed_bytes <= bufs.bytes_cap
            {
                return Err(LIST_NEEDED_WITHIN_CAP);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn blob_fmt(b: &Blob) -> Result<(), Fault> {
    if b.fmt > BLOB_OCTETS {
        return Err(BLOB_FMT);
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
            return Err(SCAN_OVER_LIMIT);
        }
        for e in entries {
            blob_fmt(&e.key)?;
            blob_fmt(&e.value)?;
            if u(e.value.len) > u(MAX_RECORD_BYTES) {
                return Err(SCAN_VALUE_OVER_MAX);
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
        return Err(OWNED_NULL_WITH_LEN);
    }
    Ok(())
}

/// A leased list's own count and array.
fn leased_count(null: bool, len: usize, seen: usize) -> Result<(), Fault> {
    if u(len) > LIST_ITEMS_HARD_MAX {
        return Err(LEASED_ITEMS_OVER_MAX);
    }
    if len > 0 && null {
        return Err(LEASED_NULL_WITH_COUNT);
    }
    if seen != len {
        return Err(LEASED_ITEMS_MISMATCH);
    }
    Ok(())
}

/// An off-path single record under a lease (`get_key`, `get_usage`, `lookup_credential_secret`).
pub fn check_leased_blob(outcome: Outcome, out: &LeasedBlobOut) -> Result<(), Fault> {
    if outcome != Outcome::Ready {
        return Ok(());
    }
    match out.found {
        ABSENT if out.record.len != 0 || !out.record.ptr.is_null() => {
            Err(LEASED_BLOB_ABSENT_WITH_RECORD)
        }
        ABSENT => Ok(()),
        FOUND => {
            blob_fmt(&out.record)?;
            owned(out.record.ptr.is_null(), out.record.len)
        }
        _ => Err(LEASED_BLOB_FOUND),
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
        return Err(VERDICT_VOCABULARY);
    }
    Ok(())
}

/// A purge's answer (`purge_windows_before`, `purge_metering_before`,
/// `purge_plane_records_before`): the rows removed. The host reads `count` on READY only, where
/// any value is the store's to state (the host sizes no buffer for it, so there is no cap); a
/// FAILED purge removed nothing, so a count on FAILED is FAULT. PENDING and REFUSED state nothing.
pub fn check_count(outcome: Outcome, out: &CountOut) -> Result<(), Fault> {
    if outcome == Outcome::Failed && out.count != 0 {
        return Err(COUNT_FAILED_WRITTEN);
    }
    Ok(())
}

/// `append_batch`'s answer: where the stream has reached. The host reads `seq` and `epoch` on
/// READY only, the store's own position (no host-side bound); a FAILED append is not the shipping
/// ack and states no head, so a `seq` or `epoch` on FAILED is FAULT. PENDING and REFUSED state
/// nothing.
pub fn check_append_batch(outcome: Outcome, out: &HeadOut) -> Result<(), Fault> {
    if outcome == Outcome::Failed && (out.seq != 0 || out.epoch != 0) {
        return Err(APPEND_FAILED_HEAD);
    }
    Ok(())
}

/// `cancel`'s answer: a store disposition only (0 UNKNOWN, 1 NOT_APPLIED, 2 APPLIED).
pub fn check_cancel(outcome: Outcome, out: &CancelOut) -> Result<(), Fault> {
    if outcome == Outcome::Ready && out.disposition > CANCEL_APPLIED {
        return Err(CANCEL_DISPOSITION);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/check_tests.rs"]
mod tests;
