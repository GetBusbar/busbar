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
    HeadsOut, HostRecords, HostSessions, RecordEntry, SessionRow, StreamHead,
};
use crate::abi::store::money::{
    CellGrant, ReleaseItem, ReserveOut, SliceReleaseOut, UnitCell, DIM_NANO_UNITS,
    RESERVE_EXHAUSTED, RESERVE_NO_CAP, RESERVE_NO_FAILED_CELL,
};
use crate::abi::store::{
    HostBlobs, HostBuf, HostBytesOut, HostListOut, LeasedBlobOut, LeasedListOut, LeasedStrListOut,
    VerdictOut, ABSENT, FOUND,
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
        Err(Fault::Vocabulary)
    );
}

#[test]
fn reserve_ready_naming_a_failed_cell_is_fault() {
    let out = reserve_out(1, 0, 0);
    assert_eq!(
        check_reserve(R, &out, &[cell(1)], 1, &[grant(1)]),
        Err(Fault::FailedCellOutOfRange)
    );
}

#[test]
fn reserve_ready_grants_over_capacity_is_fault() {
    let out = reserve_out(2, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(1), cell(1)], 1, &[grant(1)]),
        Err(Fault::CountOverCap)
    );
}

#[test]
fn reserve_ready_grants_not_one_per_cell_is_fault() {
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(1), cell(1)], 2, &[grant(1)]),
        Err(Fault::CountMismatch)
    );
}

#[test]
fn reserve_ready_a_zero_grant_is_fault() {
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(3)], 1, &[grant(0)]),
        Err(Fault::GrantOutOfRange)
    );
}

#[test]
fn reserve_ready_a_partial_grant_is_fault() {
    // S5: 1.5.5 never granted part of a draw.
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(3)], 1, &[grant(2)]),
        Err(Fault::GrantOutOfRange)
    );
}

#[test]
fn reserve_ready_a_grant_over_the_amount_is_fault() {
    let out = reserve_out(1, 0, RESERVE_NO_FAILED_CELL);
    assert_eq!(
        check_reserve(R, &out, &[cell(3)], 1, &[grant(4)]),
        Err(Fault::GrantOutOfRange)
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
        Err(Fault::WrittenOnFailed)
    );
}

#[test]
fn reserve_failed_reason_zero_is_fault() {
    let out = reserve_out(0, 0, 0);
    assert_eq!(
        check_reserve(F, &out, &[cell(1)], 1, &[]),
        Err(Fault::Vocabulary)
    );
}

#[test]
fn reserve_failed_reason_five_is_fault() {
    let out = reserve_out(0, RESERVE_NO_CAP + 1, 0);
    assert_eq!(
        check_reserve(F, &out, &[cell(1)], 1, &[]),
        Err(Fault::Vocabulary)
    );
}

#[test]
fn reserve_failed_cell_past_the_cells_is_fault() {
    let out = reserve_out(0, RESERVE_EXHAUSTED, 1);
    assert_eq!(
        check_reserve(F, &out, &[cell(1)], 1, &[]),
        Err(Fault::FailedCellOutOfRange)
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
        Err(Fault::CountOverCap)
    );
}

#[test]
fn slice_release_not_one_per_item_is_fault() {
    assert_eq!(
        check_slice_release(R, &release_out(1), &[item(1), item(1)], 2, &[1]),
        Err(Fault::CountMismatch)
    );
}

#[test]
fn slice_release_over_unspent_is_fault() {
    assert_eq!(
        check_slice_release(R, &release_out(1), &[item(2)], 1, &[3]),
        Err(Fault::ReleaseOverUnspent)
    );
}

#[test]
fn slice_release_failed_with_amounts_is_fault() {
    assert_eq!(
        check_slice_release(F, &release_out(1), &[item(2)], 1, &[]),
        Err(Fault::WrittenOnFailed)
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
        Err(Fault::Vocabulary)
    );
}

#[test]
fn needed_on_ready_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(FOUND, 1, 9), 512),
        Err(Fault::NeededNotFailed)
    );
}

#[test]
fn written_over_capacity_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(FOUND, 65, 0), 64),
        Err(Fault::CountOverCap)
    );
}

#[test]
fn a_record_over_the_record_ceiling_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(FOUND, 513, 0), 4096),
        Err(Fault::CountOverCap)
    );
}

#[test]
fn absent_with_bytes_is_fault() {
    assert_eq!(
        check_record_get(R, &bytes_out(ABSENT, 3, 0), 512),
        Err(Fault::AbsentWithLen)
    );
}

#[test]
fn failed_with_bytes_written_is_fault() {
    assert_eq!(
        check_get_plane_record(F, &bytes_out(FOUND, 1, 900), 512),
        Err(Fault::WrittenOnFailed)
    );
}

#[test]
fn needed_bytes_over_u32_max_is_fault() {
    let out = bytes_out(FOUND, 0, u64::from(u32::MAX) + 1);
    assert_eq!(
        check_get_plane_record(F, &out, 512),
        Err(Fault::NeededTooLarge)
    );
}

#[test]
fn needed_within_the_capacity_is_fault() {
    assert_eq!(
        check_get_plane_record(F, &bytes_out(FOUND, 0, 100), 512),
        Err(Fault::NeededWithinCap)
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
        Err(Fault::NeededNotFailed)
    );
}

#[test]
fn list_items_over_capacity_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(R, &list_out(5, 0, 0, 0), &host, &[]),
        Err(Fault::CountOverCap)
    );
}

#[test]
fn list_bytes_over_capacity_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(R, &list_out(0, 65, 0, 0), &host, &[]),
        Err(Fault::CountOverCap)
    );
}

#[test]
fn list_count_disagreeing_with_the_items_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let items = [b.at(0, 1)];
    assert_eq!(
        check_list_plane_records(R, &list_out(2, 1, 0, 0), &host, &items),
        Err(Fault::CountMismatch)
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
        Err(Fault::NullWithCount)
    );
}

#[test]
fn list_absent_item_with_a_length_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let items = [blob(null(), 3, BLOB_OCTETS)];
    assert_eq!(
        check_list_plane_records(R, &list_out(1, 0, 0, 0), &host, &items),
        Err(Fault::AbsentWithLen)
    );
}

#[test]
fn list_item_past_the_written_bytes_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let items = [b.at(4, 8)];
    assert_eq!(
        check_list_plane_records(R, &list_out(1, 8, 0, 0), &host, &items),
        Err(Fault::SpanOutOfBounds)
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
        Err(Fault::SpanOutOfBounds)
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
        Err(Fault::Vocabulary)
    );
}

#[test]
fn list_failed_with_items_written_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(1, 0, 9, 0), &host, &[]),
        Err(Fault::WrittenOnFailed)
    );
}

#[test]
fn list_needed_items_over_the_hard_max_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, LIST_ITEMS_HARD_MAX + 1, 0), &host, &[]),
        Err(Fault::NeededTooLarge)
    );
}

#[test]
fn list_needed_bytes_over_u32_max_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    let out = list_out(0, 0, 0, u64::from(u32::MAX) + 1);
    assert_eq!(
        check_list_plane_records(F, &out, &host, &[]),
        Err(Fault::NeededTooLarge)
    );
}

#[test]
fn list_needed_within_the_capacity_is_fault() {
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 4, 0), &host, &[]),
        Err(Fault::NeededWithinCap)
    );
    assert_eq!(
        check_list_plane_records(F, &list_out(0, 0, 0, 64), &host, &[]),
        Err(Fault::NeededWithinCap)
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
        Err(Fault::SpanOutOfBounds)
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
        Err(Fault::CountOverCap)
    );
    // A value over the record ceiling.
    let big = RecordEntry {
        key: blob(base, 2, BLOB_OCTETS),
        value: blob(base.wrapping_add(2), 513, BLOB_OCTETS),
    };
    assert_eq!(
        check_record_scan(R, &list_out(1, 515, 0, 0), &host, &[big], 4),
        Err(Fault::CountOverCap)
    );
    // A key past the written bytes.
    let past = RecordEntry {
        key: blob(base.wrapping_add(7), 2, BLOB_OCTETS),
        value: blob(base, 1, BLOB_OCTETS),
    };
    assert_eq!(
        check_record_scan(R, &list_out(1, 8, 0, 0), &host, &[past], 4),
        Err(Fault::SpanOutOfBounds)
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
        Err(Fault::AbsentWithLen)
    );
    let null_with = LeasedBlobOut {
        record: blob(null(), 2, BLOB_JSON),
        ..found
    };
    assert_eq!(check_leased_blob(R, &null_with), Err(Fault::NullWithCount));
    let bad_found = LeasedBlobOut { found: 2, ..found };
    assert_eq!(check_leased_blob(R, &bad_found), Err(Fault::Vocabulary));
    let bad_fmt = LeasedBlobOut {
        record: blob(rec.as_ptr(), 2, BLOB_OCTETS + 1),
        ..found
    };
    assert_eq!(check_leased_blob(R, &bad_fmt), Err(Fault::Vocabulary));
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
        Err(Fault::NullWithCount)
    );
    let too_many = LeasedListOut {
        items_len: (LIST_ITEMS_HARD_MAX + 1) as usize,
        ..out
    };
    assert_eq!(
        check_leased_list(R, &too_many, &items),
        Err(Fault::CountOverCap)
    );
    assert_eq!(check_leased_list(R, &out, &[]), Err(Fault::CountMismatch));
    let null_item = [blob(null(), 2, BLOB_JSON)];
    assert_eq!(
        check_leased_list(R, &out, &null_item),
        Err(Fault::NullWithCount)
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
        Err(Fault::NullWithCount)
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
    assert_eq!(check_heads(R, &hout, &bad), Err(Fault::NullWithCount));
}

#[test]
fn verdict_and_cancel_vocabularies() {
    let v = |verdict| VerdictOut {
        head: head(),
        verdict,
        _reserved: 0,
    };
    assert_eq!(check_verdict(R, &v(1)), Ok(()));
    assert_eq!(check_verdict(R, &v(2)), Err(Fault::Vocabulary));
    let c = |disposition| CancelOut {
        head: head(),
        disposition,
        _reserved: 0,
    };
    assert_eq!(check_cancel(R, &c(2)), Ok(()));
    assert_eq!(check_cancel(R, &c(3)), Err(Fault::Vocabulary));
}

#[test]
fn reserve_more_cells_than_failed_cell_can_index_is_fault() {
    assert_eq!(check_cells_len(u64::from(u32::MAX - 1)), Ok(()));
    assert_eq!(
        check_cells_len(u64::from(u32::MAX)),
        Err(Fault::CountOverCap)
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
        Err(Fault::Missing)
    );
    assert_eq!(
        check_window_caps(Outcome::Refused, 3, Some(b"conflict")),
        Err(Fault::Missing)
    );
    assert_eq!(
        check_window_caps(Outcome::Refused, 3, Some(b"3: out of range")),
        Err(Fault::CountOverCap)
    );
    assert_eq!(
        check_window_caps(Outcome::Ready, LIST_ITEMS_HARD_MAX + 1, None),
        Err(Fault::CountOverCap)
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
            Err(Fault::NeededNotFailed)
        );
    }
}

#[test]
fn reserve_needed_within_the_capacity_is_fault() {
    let cells = [cell(1), cell(1)];
    assert_eq!(
        check_reserve(F, &short_reserve(2), &cells, 2, &[]),
        Err(Fault::NeededWithinCap)
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
        Err(Fault::Vocabulary)
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
        Err(Fault::FailedCellOutOfRange)
    );
}

#[test]
fn reserve_short_answer_needing_other_than_one_grant_per_cell_is_fault() {
    assert_eq!(
        check_reserve(F, &short_reserve(3), &[cell(1), cell(1)], 1, &[]),
        Err(Fault::CountMismatch)
    );
}

#[test]
fn reserve_needed_over_the_hard_max_is_fault() {
    assert_eq!(
        check_reserve(F, &short_reserve(u64::from(u32::MAX)), &[cell(1)], 0, &[]),
        Err(Fault::NeededTooLarge)
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
        Err(Fault::NeededNotFailed)
    );
    assert_eq!(
        check_slice_release(F, &short_release(2), &items, 2, &[]),
        Err(Fault::NeededWithinCap)
    );
    assert_eq!(
        check_slice_release(F, &short_release(3), &items, 1, &[]),
        Err(Fault::CountMismatch)
    );
    assert_eq!(
        check_slice_release(F, &short_release(LIST_ITEMS_HARD_MAX + 1), &items, 1, &[]),
        Err(Fault::NeededTooLarge)
    );
}

#[test]
fn needed_with_refused_is_fault_on_reads_and_lists() {
    assert_eq!(
        check_record_get(Outcome::Refused, &bytes_out(FOUND, 0, 900), 512),
        Err(Fault::NeededNotFailed)
    );
    let mut b = Bufs::new();
    let host = b.host();
    assert_eq!(
        check_list_plane_records(Outcome::Refused, &list_out(0, 0, 9, 0), &host, &[]),
        Err(Fault::NeededNotFailed)
    );
}
