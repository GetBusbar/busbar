// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED tests for the store answer validators: one per rule, each a well-formed answer that passes
//! and the same answer broken in exactly one way that fails with the rule's [`Fault`]. Removing a
//! check turns its test red.

use super::*;
use crate::abi::mechanism::call::{
    AbiStr, Blob, Envelope, OutHead, RawOutcome, BLOB_JSON, BLOB_OCTETS,
};
use crate::abi::mechanism::lifecycle::CancelOut;
use crate::abi::store::ledger::{
    HeadOut, HeadsOut, HostRecords, HostSessions, RecordEntry, SessionRow, StreamHead,
};
use crate::abi::store::money::{
    CellGrant, ReleaseItem, ReserveOut, SliceReleaseOut, UnitCell, DIM_NANO_UNITS,
    RESERVE_EXHAUSTED, RESERVE_NO_CAP, RESERVE_NO_FAILED_CELL,
};
use crate::abi::store::{
    CountOut, HostBlobs, HostBuf, HostBytesOut, HostListOut, LeasedBlobOut, LeasedListOut,
    LeasedStrListOut, VerdictOut, ABSENT, FOUND,
};
use std::ptr::{null, null_mut};

const R: Outcome = Outcome::Ready;
const F: Outcome = Outcome::Failed;

fn head() -> OutHead {
    OutHead {
        size: 0,
        outcome: RawOutcome(0),
        _reserved: [0; 3],
        wake_at_ns: 0,
        lease: 0,
        error: AbiStr {
            ptr: null(),
            len: 0,
        },
        envelope: Envelope {
            metrics: null(),
            metrics_len: 0,
            diags: null(),
            diags_len: 0,
        },
        extensions: blob(null(), 0, 0),
    }
}

fn blob(ptr: *const u8, len: usize, fmt: u32) -> Blob {
    Blob {
        ptr,
        len,
        fmt,
        flags: 0,
    }
}

fn s(ptr: *const u8, len: usize) -> AbiStr {
    AbiStr { ptr, len }
}

// ── reserve ──────────────────────────────────────────────────────────────────────────────────

fn cell(amount: u64) -> UnitCell {
    UnitCell {
        bucket: s(b"b".as_ptr(), 1),
        pool: s(null(), 0),
        dimension: DIM_NANO_UNITS,
        _r: 0,
        class_key: s(null(), 0),
        amount,
        window_start: 0,
    }
}

fn grant(granted: u64) -> CellGrant {
    CellGrant {
        slice_id: 7,
        granted,
        valid_until_ms: 1,
    }
}

fn reserve_out(grants_len: usize, reason: u32, failed_cell: u32) -> ReserveOut {
    ReserveOut {
        head: head(),
        grants_len,
        reason,
        failed_cell,
        needed_grants: 0,
    }
}

#[test]
fn reserve_ready_well_formed_passes() {
    let cells = [cell(10), cell(5)];
    let out = reserve_out(2, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &cells, 2, &[grant(10), grant(5)]),
        Ok(())
    );
}

#[test]
fn reserve_ready_with_a_reason_is_fault() {
    let out = reserve_out(1, RESERVE_EXHAUSTED, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(1)], 1, &[grant(1)]),
        Err(RESERVE_READY_REASON)
    );
}

#[test]
fn reserve_ready_naming_a_failed_cell_is_fault() {
    let out = reserve_out(1, 0, 0);
    assert_eq!(
        check_reserve(R, &out, &[cell(1)], 1, &[grant(1)]),
        Err(RESERVE_READY_FAILED_CELL)
    );
}

#[test]
fn reserve_ready_grants_over_capacity_is_fault() {
    let out = reserve_out(2, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(1), cell(1)], 1, &[grant(1)]),
        Err(RESERVE_GRANTS_OVER_CAP)
    );
}

#[test]
fn reserve_ready_grants_not_one_per_cell_is_fault() {
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(1), cell(1)], 2, &[grant(1)]),
        Err(RESERVE_GRANTS_MISMATCH)
    );
}

#[test]
fn reserve_ready_a_zero_grant_is_fault() {
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(3)], 1, &[grant(0)]),
        Err(RESERVE_GRANT_NOT_WHOLE)
    );
}

#[test]
fn reserve_ready_a_partial_grant_is_fault() {
    // S5: 1.5.5 never granted part of a draw.
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(3)], 1, &[grant(2)]),
        Err(RESERVE_GRANT_NOT_WHOLE)
    );
}

#[test]
fn reserve_ready_a_grant_over_the_amount_is_fault() {
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(3)], 1, &[grant(4)]),
        Err(RESERVE_GRANT_NOT_WHOLE)
    );
}

#[test]
fn reserve_failed_well_formed_passes() {
    let cells = [cell(1), cell(1)];
    for reason in 1..=RESERVE_NO_CAP {
        assert_eq!(
            check_reserve(F, &reserve_out(0, reason, 1), &cells, 2, &[]),
            Ok(())
        );
    }
    let none = reserve_out(0, RESERVE_NO_CAP, RESERVE_NO_FAILED_CELL);
    assert_eq!(check_reserve(F, &none, &cells, 2, &[]), Ok(()));
}

#[test]
fn reserve_failed_with_grants_is_fault() {
    let out = reserve_out(1, RESERVE_EXHAUSTED, 0);
    assert_eq!(
        check_reserve(F, &out, &[cell(1)], 1, &[]),
        Err(RESERVE_FAILED_GRANTS_WRITTEN)
    );
}

#[test]
fn reserve_failed_reason_zero_is_fault() {
    let out = reserve_out(0, 0, 0);
    assert_eq!(
        check_reserve(F, &out, &[cell(1)], 1, &[]),
        Err(RESERVE_FAILED_REASON)
    );
}

#[test]
fn reserve_failed_reason_five_is_fault() {
    let out = reserve_out(0, RESERVE_NO_CAP + 1, 0);
    assert_eq!(
        check_reserve(F, &out, &[cell(1)], 1, &[]),
        Err(RESERVE_FAILED_REASON)
    );
}

#[test]
fn reserve_failed_cell_past_the_cells_is_fault() {
    let out = reserve_out(0, RESERVE_EXHAUSTED, 1);
    assert_eq!(
        check_reserve(F, &out, &[cell(1)], 1, &[]),
        Err(RESERVE_FAILED_CELL)
    );
}

// ── slice_release ────────────────────────────────────────────────────────────────────────────

fn item(unspent: u64) -> ReleaseItem {
    ReleaseItem {
        slice_id: 1,
        unspent,
    }
}

fn release_out(released_len: usize) -> SliceReleaseOut {
    SliceReleaseOut {
        head: head(),
        released_len,
        needed_released: 0,
    }
}

#[test]
fn slice_release_clamped_passes() {
    let items = [item(5), item(0)];
    assert_eq!(
        check_slice_release(R, &release_out(2), &items, 2, &[3, 0]),
        Ok(())
    );
}

#[test]
fn slice_release_over_capacity_is_fault() {
    assert_eq!(
        check_slice_release(R, &release_out(2), &[item(1), item(1)], 1, &[1]),
        Err(SLICE_RELEASED_OVER_CAP)
    );
}

#[test]
fn slice_release_not_one_per_item_is_fault() {
    assert_eq!(
        check_slice_release(R, &release_out(1), &[item(1), item(1)], 2, &[1]),
        Err(SLICE_RELEASED_MISMATCH)
    );
}

#[test]
fn slice_release_over_unspent_is_fault() {
    assert_eq!(
        check_slice_release(R, &release_out(1), &[item(2)], 1, &[3]),
        Err(SLICE_RELEASE_OVER_UNSPENT)
    );
}

#[test]
fn slice_release_failed_with_amounts_is_fault() {
    assert_eq!(
        check_slice_release(F, &release_out(1), &[item(2)], 1, &[]),
        Err(SLICE_FAILED_WRITTEN)
    );
}

// ── single-value reads ───────────────────────────────────────────────────────────────────────

fn bytes_out(found: u32, written: u64, needed: u64) -> HostBytesOut {
    HostBytesOut {
        head: head(),
        found,
        _reserved: 0,
        written,
        needed,
    }
}

#[test]
fn record_get_well_formed_passes() {
    assert_eq!(check_record_get(R, &bytes_out(FOUND, 12, 0), 512), Ok(()));
    assert_eq!(check_record_get(R, &bytes_out(ABSENT, 0, 0), 512), Ok(()));
    assert_eq!(
        check_get_plane_record(F, &bytes_out(FOUND, 0, 900), 512),
        Ok(())
    );
}

#[test]
fn a_found_outside_the_vocabulary_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(2, 0, 0), 512),
        Err(BYTES_FOUND)
    );
}

#[test]
fn needed_on_ready_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(FOUND, 1, 9), 512),
        Err(NEEDED_NOT_FAILED)
    );
}

#[test]
fn written_over_capacity_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(FOUND, 65, 0), 64),
        Err(BYTES_WRITTEN_OVER_CAP)
    );
}

#[test]
fn a_record_over_the_record_ceiling_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(FOUND, 513, 0), 4096),
        Err(BYTES_WRITTEN_OVER_CAP)
    );
}

#[test]
fn absent_with_bytes_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(ABSENT, 3, 0), 512),
        Err(BYTES_ABSENT_WRITTEN)
    );
}

#[test]
fn failed_with_bytes_written_is_fault() {
    assert_eq!(
        check_get_plane_record(F, &bytes_out(FOUND, 1, 900), 512),
        Err(BYTES_FAILED_WRITTEN)
    );
}

#[test]
fn needed_bytes_over_u32_max_is_fault() {
    let out = bytes_out(FOUND, 0, u64::from(u32::MAX) + 1);
    assert_eq!(
        check_get_plane_record(F, &out, 512),
        Err(BYTES_NEEDED_TOO_LARGE)
    );
}

#[test]
fn needed_within_the_capacity_is_fault() {
    assert_eq!(
        check_get_plane_record(F, &bytes_out(FOUND, 0, 100), 512),
        Err(BYTES_NEEDED_WITHIN_CAP)
    );
}

// ── request-path lists ───────────────────────────────────────────────────────────────────────

fn list_out(iw: u64, bw: u64, ni: u64, nb: u64) -> HostListOut {
    HostListOut {
        head: head(),
        items_written: iw,
        bytes_written: bw,
        needed_items: ni,
        needed_bytes: nb,
    }
}

/// Host buffers for a list test: a real byte buffer, so spans are real addresses.
struct Bufs {
    bytes: Vec<u8>,
    items: Vec<Blob>,
}

impl Bufs {
    fn new() -> Self {
        Bufs {
            bytes: vec![0; 64],
            items: vec![blob(null(), 0, 0); 4],
        }
    }
    fn host(&mut self) -> HostBlobs {
        HostBlobs {
            items: self.items.as_mut_ptr(),
            items_cap: self.items.len(),
            bytes: HostBuf {
                ptr: self.bytes.as_mut_ptr(),
                cap: self.bytes.len(),
            },
        }
    }
    fn at(&self, off: usize, len: usize) -> Blob {
        blob(self.bytes.as_ptr().wrapping_add(off), len, BLOB_OCTETS)
    }
}

#[test]
fn list_well_formed_passes() {
    let mut b = Bufs::new();
    let host = b.host();
    let items = [b.at(0, 8), b.at(8, 8)];
    assert_eq!(
        check_list_plane_records(R, &list_out(2, 16, 0, 0), &host, &items),
        Ok(())
    );
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 9, 0), &host, &[]),
        Ok(())
    );
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 0, 65), &host, &[]),
        Ok(())
    );
}

#[test]
fn list_needed_on_ready_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(R, &list_out(0, 0, 1, 0), &host, &[]),
        Err(NEEDED_NOT_FAILED)
    );
}

#[test]
fn list_items_over_capacity_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(R, &list_out(5, 0, 0, 0), &host, &[]),
        Err(LIST_WRITTEN_OVER_CAP)
    );
}

#[test]
fn list_bytes_over_capacity_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(R, &list_out(0, 65, 0, 0), &host, &[]),
        Err(LIST_WRITTEN_OVER_CAP)
    );
}

#[test]
fn list_count_disagreeing_with_the_items_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let items = [b.at(0, 1)];
    assert_eq!(
        check_list_plane_records(R, &list_out(2, 1, 0, 0), &host, &items),
        Err(LIST_ITEMS_MISMATCH)
    );
}

#[test]
fn list_count_with_a_null_array_is_fault() {
    let mut b = Bufs::new();
    let mut host = b.host();
    host.items = null_mut();
    let items = [b.at(0, 1)];
    assert_eq!(
        check_list_plane_records(R, &list_out(1, 1, 0, 0), &host, &items),
        Err(LIST_NULL_WITH_COUNT)
    );
}

#[test]
fn list_absent_item_with_a_length_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let items = [blob(null(), 3, BLOB_OCTETS)];
    assert_eq!(
        check_list_plane_records(R, &list_out(1, 0, 0, 0), &host, &items),
        Err(SPAN_ABSENT_WITH_LEN)
    );
}

#[test]
fn list_item_past_the_written_bytes_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let items = [b.at(4, 8)];
    assert_eq!(
        check_list_plane_records(R, &list_out(1, 8, 0, 0), &host, &items),
        Err(SPAN_OUT_OF_BOUNDS)
    );
}

#[test]
fn list_item_outside_the_host_buffer_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let elsewhere = [0u8; 4];
    let items = [blob(elsewhere.as_ptr(), 4, BLOB_OCTETS)];
    assert_eq!(
        check_list_plane_records(R, &list_out(1, 4, 0, 0), &host, &items),
        Err(SPAN_OUT_OF_BOUNDS)
    );
}

#[test]
fn list_blob_format_outside_the_vocabulary_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let mut bad = b.at(0, 1);
    bad.fmt = BLOB_OCTETS + 1;
    assert_eq!(
        check_list_plane_records(R, &list_out(1, 1, 0, 0), &host, &[bad]),
        Err(BLOB_FMT)
    );
}

#[test]
fn list_failed_with_items_written_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(1, 0, 9, 0), &host, &[]),
        Err(LIST_FAILED_WRITTEN)
    );
}

#[test]
fn list_needed_items_over_the_hard_max_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, LIST_ITEMS_HARD_MAX + 1, 0), &host, &[]),
        Err(LIST_NEEDED_TOO_LARGE)
    );
}

#[test]
fn list_needed_bytes_over_u32_max_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let out = list_out(0, 0, 0, u64::from(u32::MAX) + 1);
    assert_eq!(
        check_list_plane_records(F, &out, &host, &[]),
        Err(LIST_NEEDED_TOO_LARGE)
    );
}

#[test]
fn list_short_in_one_dimension_with_the_other_fitting_is_legal() {
    // M-SB REFINEMENT: items over their cap (4), bytes at their full size that fits (10 <= 64).
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 5, 10), &host, &[]),
        Ok(())
    );
    // Bytes over their cap (64), items at their full size that fits (2 <= 4).
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 2, 65), &host, &[]),
        Ok(())
    );
}

#[test]
fn list_short_with_both_dimensions_fitting_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 2, 10), &host, &[]),
        Err(LIST_NEEDED_WITHIN_CAP)
    );
}

#[test]
fn list_needed_within_the_capacity_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 4, 0), &host, &[]),
        Err(LIST_NEEDED_WITHIN_CAP)
    );
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 0, 64), &host, &[]),
        Err(LIST_NEEDED_WITHIN_CAP)
    );
}

#[test]
fn sessions_for_checks_each_node_string() {
    let mut bytes = vec![0u8; 16];
    let mut rows = vec![
        SessionRow {
            session: 1,
            node: s(null(), 0),
        };
        2
    ];
    let host = HostSessions {
        items: rows.as_mut_ptr(),
        items_cap: 2,
        bytes: HostBuf {
            ptr: bytes.as_mut_ptr(),
            cap: 16,
        },
    };
    let ok = [SessionRow {
        session: 1,
        node: s(bytes.as_ptr(), 4),
    }];
    assert_eq!(
        check_sessions_for(R, &list_out(1, 4, 0, 0), &host, &ok),
        Ok(())
    );
    let past = [SessionRow {
        session: 1,
        node: s(bytes.as_ptr().wrapping_add(2), 4),
    }];
    assert_eq!(
        check_sessions_for(R, &list_out(1, 4, 0, 0), &host, &past),
        Err(SPAN_OUT_OF_BOUNDS)
    );
}

fn records_host(bytes: &mut [u8], slots: &mut [RecordEntry]) -> HostRecords {
    HostRecords {
        items: slots.as_mut_ptr(),
        items_cap: slots.len(),
        bytes: HostBuf {
            ptr: bytes.as_mut_ptr(),
            cap: bytes.len(),
        },
    }
}

#[test]
fn record_scan_checks_limit_keys_and_values() {
    let mut bytes = vec![0u8; 2048];
    let base = bytes.as_ptr();
    let empty = RecordEntry {
        key: blob(null(), 0, 0),
        value: blob(null(), 0, 0),
    };
    let mut slots = vec![empty; 4];
    let host = records_host(&mut bytes, &mut slots);
    let e = RecordEntry {
        key: blob(base, 2, BLOB_OCTETS),
        value: blob(base.wrapping_add(2), 6, BLOB_OCTETS),
    };
    assert_eq!(
        check_record_scan(R, &list_out(1, 8, 0, 0), &host, &[e], 4),
        Ok(())
    );
    // More entries than the scan's limit (limit 0 means nothing).
    assert_eq!(
        check_record_scan(R, &list_out(1, 8, 0, 0), &host, &[e], 0),
        Err(SCAN_OVER_LIMIT)
    );
    // A value over the record ceiling.
    let big = RecordEntry {
        key: blob(base, 2, BLOB_OCTETS),
        value: blob(base.wrapping_add(2), 513, BLOB_OCTETS),
    };
    assert_eq!(
        check_record_scan(R, &list_out(1, 515, 0, 0), &host, &[big], 4),
        Err(SCAN_VALUE_OVER_MAX)
    );
    // A key past the written bytes.
    let past = RecordEntry {
        key: blob(base.wrapping_add(7), 2, BLOB_OCTETS),
        value: blob(base, 1, BLOB_OCTETS),
    };
    assert_eq!(
        check_record_scan(R, &list_out(1, 8, 0, 0), &host, &[past], 4),
        Err(SPAN_OUT_OF_BOUNDS)
    );
}

// ── leased (off-path) answers ────────────────────────────────────────────────────────────────

#[test]
fn leased_blob_rules() {
    let rec = b"{}";
    let found = LeasedBlobOut {
        head: head(),
        found: FOUND,
        _reserved: 0,
        record: blob(rec.as_ptr(), 2, BLOB_JSON),
    };
    assert_eq!(check_leased_blob(R, &found), Ok(()));
    let absent = LeasedBlobOut {
        found: ABSENT,
        record: blob(null(), 0, 0),
        ..found
    };
    assert_eq!(check_leased_blob(R, &absent), Ok(()));
    let absent_with = LeasedBlobOut {
        found: ABSENT,
        ..found
    };
    assert_eq!(
        check_leased_blob(R, &absent_with),
        Err(LEASED_BLOB_ABSENT_WITH_RECORD)
    );
    let null_with = LeasedBlobOut {
        record: blob(null(), 2, BLOB_JSON),
        ..found
    };
    assert_eq!(check_leased_blob(R, &null_with), Err(OWNED_NULL_WITH_LEN));
    let bad_found = LeasedBlobOut { found: 2, ..found };
    assert_eq!(check_leased_blob(R, &bad_found), Err(LEASED_BLOB_FOUND));
    let bad_fmt = LeasedBlobOut {
        record: blob(rec.as_ptr(), 2, BLOB_OCTETS + 1),
        ..found
    };
    assert_eq!(check_leased_blob(R, &bad_fmt), Err(BLOB_FMT));
}

#[test]
fn leased_list_rules() {
    let rec = b"{}";
    let items = [blob(rec.as_ptr(), 2, BLOB_JSON)];
    let out = LeasedListOut {
        head: head(),
        items: items.as_ptr(),
        items_len: 1,
    };
    assert_eq!(check_leased_list(R, &out, &items), Ok(()));
    let null_arr = LeasedListOut {
        items: null(),
        ..out
    };
    assert_eq!(
        check_leased_list(R, &null_arr, &items),
        Err(LEASED_NULL_WITH_COUNT)
    );
    let too_many = LeasedListOut {
        items_len: (LIST_ITEMS_HARD_MAX + 1) as usize,
        ..out
    };
    assert_eq!(
        check_leased_list(R, &too_many, &items),
        Err(LEASED_ITEMS_OVER_MAX)
    );
    assert_eq!(check_leased_list(R, &out, &[]), Err(LEASED_ITEMS_MISMATCH));
    let null_item = [blob(null(), 2, BLOB_JSON)];
    assert_eq!(
        check_leased_list(R, &out, &null_item),
        Err(OWNED_NULL_WITH_LEN)
    );
}

#[test]
fn leased_strings_and_heads_rules() {
    let name = b"stream";
    let strs = [s(name.as_ptr(), 6)];
    let out = LeasedStrListOut {
        head: head(),
        items: strs.as_ptr(),
        items_len: 1,
    };
    assert_eq!(check_leased_strs(R, &out, &strs), Ok(()));
    assert_eq!(
        check_leased_strs(R, &out, &[s(null(), 1)]),
        Err(OWNED_NULL_WITH_LEN)
    );
    let heads = [StreamHead {
        stream: s(name.as_ptr(), 6),
        seq: 1,
        epoch: 1,
    }];
    let hout = HeadsOut {
        head: head(),
        items: heads.as_ptr(),
        items_len: 1,
    };
    assert_eq!(check_heads(R, &hout, &heads), Ok(()));
    let bad = [StreamHead {
        stream: s(null(), 6),
        ..heads[0]
    }];
    assert_eq!(check_heads(R, &hout, &bad), Err(OWNED_NULL_WITH_LEN));
}

#[test]
fn verdict_and_cancel_vocabularies() {
    let v = |verdict| VerdictOut {
        head: head(),
        verdict,
        _reserved: 0,
    };
    assert_eq!(check_verdict(R, &v(1)), Ok(()));
    assert_eq!(check_verdict(R, &v(2)), Err(VERDICT_VOCABULARY));
    let c = |disposition| CancelOut {
        head: head(),
        disposition,
        _reserved: 0,
    };
    assert_eq!(check_cancel(R, &c(2)), Ok(()));
    assert_eq!(check_cancel(R, &c(3)), Err(CANCEL_DISPOSITION));
}

#[test]
fn reserve_more_cells_than_failed_cell_can_index_is_fault() {
    assert_eq!(check_cells_len(u64::from(u32::MAX - 1)), Ok(()));
    assert_eq!(
        check_cells_len(u64::from(u32::MAX)),
        Err(RESERVE_CELLS_OVER_MAX)
    );
}

#[test]
fn window_caps_refusal_names_a_cap() {
    assert_eq!(check_window_caps(Outcome::Ready, 3, None), Ok(()));
    assert_eq!(
        check_window_caps(Outcome::Refused, 3, Some(b"2: STORE_CAP_CONFLICT")),
        Ok(())
    );
    assert_eq!(
        check_window_caps(Outcome::Refused, 3, None),
        Err(WINDOW_ERROR_MISSING)
    );
    assert_eq!(
        check_window_caps(Outcome::Refused, 3, Some(b"conflict")),
        Err(WINDOW_ERROR_INDEX_MISSING)
    );
    assert_eq!(
        check_window_caps(Outcome::Refused, 3, Some(b"3: out of range")),
        Err(WINDOW_ERROR_INDEX_OVER)
    );
    assert_eq!(
        check_window_caps(Outcome::Ready, LIST_ITEMS_HARD_MAX + 1, None),
        Err(WINDOW_CAPS_OVER_MAX)
    );
}

#[test]
fn window_caps_refusal_may_name_an_op_id_conflict() {
    assert_eq!(
        check_window_caps(
            Outcome::Refused,
            1,
            Some(b"STORE_OPID_CONFLICT: the op_id was already used with different value fields")
        ),
        Ok(())
    );
}

// ── M-SB: the short-buffer answer ────────────────────────────────────────────────────────────

fn short_reserve(needed: u64) -> ReserveOut {
    ReserveOut {
        needed_grants: needed,
        ..reserve_out(0, 0, RESERVE_NO_FAILED_CELL)
    }
}

#[test]
fn reserve_short_answer_passes() {
    let cells = [cell(1), cell(1)];
    assert_eq!(check_reserve(F, &short_reserve(2), &cells, 1, &[]), Ok(()));
}

#[test]
fn reserve_needed_with_a_non_failed_outcome_is_fault() {
    let cells = [cell(1)];
    for o in [R, Outcome::Refused, Outcome::Pending] {
        assert_eq!(
            check_reserve(o, &short_reserve(2), &cells, 1, &[grant(1)]),
            Err(NEEDED_NOT_FAILED)
        );
    }
}

#[test]
fn reserve_needed_within_the_capacity_is_fault() {
    let cells = [cell(1), cell(1)];
    assert_eq!(
        check_reserve(F, &short_reserve(2), &cells, 2, &[]),
        Err(RESERVE_NEEDED_WITHIN_CAP)
    );
}

#[test]
fn reserve_short_answer_with_a_reason_is_fault() {
    let out = ReserveOut {
        reason: RESERVE_EXHAUSTED,
        ..short_reserve(2)
    };
    assert_eq!(
        check_reserve(F, &out, &[cell(1), cell(1)], 1, &[]),
        Err(RESERVE_SHORT_REASON)
    );
}

#[test]
fn reserve_short_answer_naming_a_cell_is_fault() {
    let out = ReserveOut {
        failed_cell: 0,
        ..short_reserve(2)
    };
    assert_eq!(
        check_reserve(F, &out, &[cell(1), cell(1)], 1, &[]),
        Err(RESERVE_SHORT_FAILED_CELL)
    );
}

#[test]
fn reserve_short_answer_needing_other_than_one_grant_per_cell_is_fault() {
    assert_eq!(
        check_reserve(F, &short_reserve(3), &[cell(1), cell(1)], 1, &[]),
        Err(RESERVE_NEEDED_MISMATCH)
    );
}

#[test]
fn reserve_needed_over_the_hard_max_is_fault() {
    assert_eq!(
        check_reserve(F, &short_reserve(u64::from(u32::MAX)), &[cell(1)], 0, &[]),
        Err(RESERVE_NEEDED_TOO_LARGE)
    );
}

fn short_release(needed: u64) -> SliceReleaseOut {
    SliceReleaseOut {
        needed_released: needed,
        ..release_out(0)
    }
}

#[test]
fn slice_release_short_answer_rules() {
    let items = [item(1), item(1)];
    assert_eq!(
        check_slice_release(F, &short_release(2), &items, 1, &[]),
        Ok(())
    );
    assert_eq!(
        check_slice_release(R, &short_release(2), &items, 2, &[1, 1]),
        Err(NEEDED_NOT_FAILED)
    );
    assert_eq!(
        check_slice_release(F, &short_release(2), &items, 2, &[]),
        Err(SLICE_NEEDED_WITHIN_CAP)
    );
    assert_eq!(
        check_slice_release(F, &short_release(3), &items, 1, &[]),
        Err(SLICE_NEEDED_MISMATCH)
    );
    assert_eq!(
        check_slice_release(F, &short_release(LIST_ITEMS_HARD_MAX + 1), &items, 1, &[]),
        Err(SLICE_NEEDED_TOO_LARGE)
    );
}

#[test]
fn needed_with_refused_is_fault_on_reads_and_lists() {
    assert_eq!(
        check_record_get(Outcome::Refused, &bytes_out(FOUND, 0, 900), 512),
        Err(NEEDED_NOT_FAILED)
    );
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(Outcome::Refused, &list_out(0, 0, 9, 0), &host, &[]),
        Err(NEEDED_NOT_FAILED)
    );
}

// ── every outcome: a zeroed `out` on PENDING or REFUSED passes ──────────────────────────────

#[test]
fn a_found_outside_the_vocabulary_is_read_on_ready_only() {
    assert_eq!(check_record_get(F, &bytes_out(2, 0, 0), 512), Ok(()));
    assert_eq!(
        check_record_get(Outcome::Refused, &bytes_out(2, 0, 0), 512),
        Ok(())
    );
}

#[test]
fn a_zeroed_out_on_pending_or_refused_passes_every_validator() {
    let mut b = Bufs::new();
    let host = b.host();
    let cells = [cell(5)];
    let items = [item(3)];
    for o in [Outcome::Pending, Outcome::Refused] {
        assert_eq!(
            check_reserve(o, &reserve_out(0, 0, 0), &cells, 1, &[]),
            Ok(())
        );
        assert_eq!(
            check_slice_release(o, &release_out(0), &items, 1, &[]),
            Ok(())
        );
        assert_eq!(check_record_get(o, &bytes_out(0, 0, 0), 512), Ok(()));
        assert_eq!(check_get_plane_record(o, &bytes_out(0, 0, 0), 512), Ok(()));
        assert_eq!(
            check_list_plane_records(o, &list_out(0, 0, 0, 0), &host, &[]),
            Ok(())
        );
        assert_eq!(check_count(o, &count_out(0)), Ok(()));
        assert_eq!(check_append_batch(o, &head_out(0, 0)), Ok(()));
        assert_eq!(
            check_verdict(
                o,
                &VerdictOut {
                    head: head(),
                    verdict: 0,
                    _reserved: 0
                }
            ),
            Ok(())
        );
    }
    assert_eq!(check_window_caps(Outcome::Pending, 3, None), Ok(()));
}

// ── purges: the rows removed ─────────────────────────────────────────────────────────────────

fn count_out(count: u64) -> CountOut {
    CountOut {
        head: head(),
        count,
    }
}

#[test]
fn count_ready_passes() {
    assert_eq!(check_count(R, &count_out(0)), Ok(()));
    assert_eq!(check_count(R, &count_out(u64::MAX)), Ok(()));
    assert_eq!(check_count(F, &count_out(0)), Ok(()));
}

#[test]
fn count_on_failed_is_fault() {
    assert_eq!(check_count(F, &count_out(1)), Err(COUNT_FAILED_WRITTEN));
}

// ── append_batch: the shipping ack's head ────────────────────────────────────────────────────

fn head_out(seq: u64, epoch: u64) -> HeadOut {
    HeadOut {
        head: head(),
        seq,
        epoch,
    }
}

#[test]
fn append_batch_ready_passes() {
    assert_eq!(check_append_batch(R, &head_out(41, 3)), Ok(()));
    assert_eq!(check_append_batch(F, &head_out(0, 0)), Ok(()));
}

#[test]
fn append_batch_seq_on_failed_is_fault() {
    assert_eq!(
        check_append_batch(F, &head_out(41, 0)),
        Err(APPEND_FAILED_HEAD)
    );
}

#[test]
fn append_batch_epoch_on_failed_is_fault() {
    assert_eq!(
        check_append_batch(F, &head_out(0, 3)),
        Err(APPEND_FAILED_HEAD)
    );
}

// ── a distinct fault field per arm (SPEC §11.13 "a distinct message per arm") ────────────────

/// The field a reserve answer's FAULT names.
fn reserve_field(
    outcome: Outcome,
    out: &ReserveOut,
    cells: &[UnitCell],
    grants: &[CellGrant],
) -> &'static str {
    check_reserve(outcome, out, cells, 2, grants)
        .expect_err("the answer is built to be a FAULT")
        .field
}

#[test]
fn reserve_ready_with_a_reason_names_its_own_field() {
    let out = reserve_out(1, RESERVE_EXHAUSTED, RESERVE_NO_FAILED_CELL);
    let field = reserve_field(R, &out, &[cell(1)], &[grant(1)]);
    assert_eq!(field, "store.reserve.ready_reason");
}

#[test]
fn reserve_short_answer_with_a_reason_names_its_own_field() {
    let out = ReserveOut {
        reason: RESERVE_EXHAUSTED,
        ..short_reserve(3)
    };
    let field = reserve_field(F, &out, &[cell(1), cell(1), cell(1)], &[]);
    assert_eq!(field, "store.reserve.short_reason");
}

#[test]
fn reserve_failed_with_a_reason_out_of_range_names_its_own_field() {
    let out = reserve_out(0, RESERVE_NO_CAP + 1, RESERVE_NO_FAILED_CELL);
    let field = reserve_field(F, &out, &[cell(1)], &[]);
    assert_eq!(field, "store.reserve.failed_reason");
}

#[test]
fn reserve_arms_that_share_a_rule_do_not_share_a_field() {
    let ready = reserve_field(
        R,
        &reserve_out(1, RESERVE_EXHAUSTED, RESERVE_NO_FAILED_CELL),
        &[cell(1)],
        &[grant(1)],
    );
    let short = reserve_field(
        F,
        &ReserveOut {
            reason: RESERVE_EXHAUSTED,
            ..short_reserve(3)
        },
        &[cell(1), cell(1), cell(1)],
        &[],
    );
    let failed = reserve_field(
        F,
        &reserve_out(0, RESERVE_NO_CAP + 1, RESERVE_NO_FAILED_CELL),
        &[cell(1)],
        &[],
    );
    assert_ne!(ready, short);
    assert_ne!(ready, failed);
    assert_ne!(short, failed);
}

#[test]
fn every_store_fault_names_its_own_store_field() {
    let mut seen = std::collections::BTreeSet::new();
    for f in ALL {
        assert!(f.field.starts_with("store."), "{}", f.field);
        assert!(seen.insert(f.field), "{} is named by two arms", f.field);
    }
    assert_eq!(seen.len(), ALL.len());
}
