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
use crate::abi::store::ledger::{HostRecords, RecordEntry};
use crate::abi::store::plane::{
    KindBeforeIn, RETENTION_AGE, RETENTION_TERMINAL_ONLY, RETENTION_USAGE_WINDOWS,
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
fn leased_strings_rules() {
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

// ── M-SB: the short-buffer answer ────────────────────────────────────────────────────────────

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
    for o in [Outcome::Pending, Outcome::Refused] {
        assert_eq!(check_record_get(o, &bytes_out(0, 0, 0), 512), Ok(()));
        assert_eq!(check_get_plane_record(o, &bytes_out(0, 0, 0), 512), Ok(()));
        assert_eq!(
            check_list_plane_records(o, &list_out(0, 0, 0, 0), &host, &[]),
            Ok(())
        );
        assert_eq!(check_count(o, &count_out(0)), Ok(()));
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

// ── a distinct fault field per arm (the design: "a distinct message per arm") ────────────────

#[test]
fn every_store_fault_names_its_own_store_field() {
    let mut seen = std::collections::BTreeSet::new();
    for f in ALL {
        assert!(f.field.starts_with("store."), "{}", f.field);
        assert!(seen.insert(f.field), "{} is named by two arms", f.field);
    }
    assert_eq!(seen.len(), ALL.len());
}

fn kind_before(retention: u32) -> KindBeforeIn {
    // SAFETY: `KindBeforeIn` is `#[repr(C)]` integers and pointers; all-zero is a valid value.
    let mut i: KindBeforeIn = unsafe { std::mem::zeroed() };
    i.before = 100;
    i.retention = retention;
    i
}

/// GREEN: each rule a purge may carry passes, and the zero an older host's shorter `in` reads as
/// is the age rule.
#[test]
fn green_a_purge_carries_a_known_retention() {
    assert_eq!(check_kind_before(&kind_before(RETENTION_AGE)), Ok(()));
    assert_eq!(
        check_kind_before(&kind_before(RETENTION_TERMINAL_ONLY)),
        Ok(())
    );
    assert_eq!(
        check_kind_before(&kind_before(RETENTION_USAGE_WINDOWS)),
        Ok(())
    );
    assert_eq!(RETENTION_AGE, 0);
    assert_eq!(
        crate::records::Retention::from_code(0),
        Some(crate::records::Retention::Age)
    );
}

/// RED: a purge whose retention names no rule is refused.
#[test]
fn red_a_purge_with_an_unknown_retention_is_refused() {
    for code in [RETENTION_USAGE_WINDOWS + 1, u32::MAX] {
        assert_eq!(
            check_kind_before(&kind_before(code)),
            Err(KIND_BEFORE_RETENTION)
        );
    }
}

/// The contract rule and its code map both ways.
#[test]
fn a_retention_and_its_code_map_both_ways() {
    use crate::records::Retention;
    for r in [Retention::Age, Retention::TerminalOnly] {
        assert_eq!(Retention::from_code(r.code()), Some(r));
    }
    assert_eq!(Retention::default(), Retention::Age);
}

// ── the kind's answer check (`check_answer`): frames, then the op's validator ───────────────

/// `check_answer` for a store slot over an `in` and an `out` of the stated sizes.
fn answer<I, O>(
    slot: u32,
    outcome: Outcome,
    input: &I,
    in_size: usize,
    out: &O,
    out_size: usize,
) -> Result<(), Fault> {
    // SAFETY: both frames are live locals of at least the sizes stated, each leading with its
    // head; no lent buffer is named.
    unsafe {
        check_answer(
            slot,
            outcome,
            (&raw const *input).cast(),
            in_size,
            (&raw const *out).cast(),
            out_size,
            &(),
        )
    }
}

/// `record_get` reads its `in` first, then its `out`, and is judged against the capacity its `in`
/// lent; `get_usage` is a leased blob; `cancel` its disposition; a bare-head op passes.
#[test]
fn check_answer_reads_the_frames_in_order_then_judges_the_op() {
    use crate::abi::store::{slot, RecordGetIn};
    use std::mem::size_of;
    // SAFETY: an all-zero `RecordGetIn` is a valid value (plain data: integers, NULL pointers).
    let mut input: RecordGetIn = unsafe { std::mem::zeroed() };
    input.value.cap = 512;
    let (is, os) = (size_of::<RecordGetIn>(), size_of::<HostBytesOut>());
    let fits = bytes_out(FOUND, 512, 0);
    assert_eq!(answer(slot::RECORD_GET, R, &input, is, &fits, os), Ok(()));
    let over = bytes_out(FOUND, 513, 0);
    assert_eq!(
        answer(slot::RECORD_GET, R, &input, is, &over, os),
        Err(BYTES_WRITTEN_OVER_CAP)
    );
    assert_eq!(
        answer(slot::RECORD_GET, R, &input, is - 1, &fits, os - 1),
        Err(fault(Rule::Foreign, "in"))
    );
    assert_eq!(
        answer(slot::RECORD_GET, R, &input, is, &fits, os - 1),
        Err(fault(Rule::Foreign, "out"))
    );

    let leased = LeasedBlobOut {
        head: head(),
        found: 7,
        _reserved: 0,
        record: blob(null(), 0, 0),
    };
    let (hs, ls) = (
        size_of::<crate::abi::mechanism::call::InHead>(),
        size_of::<LeasedBlobOut>(),
    );
    assert_eq!(
        answer(slot::GET_USAGE, R, &input, hs, &leased, ls),
        Err(LEASED_BLOB_FOUND)
    );
    // An op reading its `out` alone never size-checks the `in`.
    assert_eq!(
        answer(slot::GET_KEY, R, &input, 0, &leased, ls - 1),
        Err(fault(Rule::Foreign, "out"))
    );

    let cancel = CancelOut {
        head: head(),
        disposition: CANCEL_APPLIED + 1,
        _reserved: 0,
    };
    assert_eq!(
        answer(life::CANCEL, R, &input, hs, &cancel, size_of::<CancelOut>()),
        Err(CANCEL_DISPOSITION)
    );
    assert_eq!(answer(slot::PUT_KEY, R, &input, 0, &fits, 0), Ok(()));
}

/// A leased list is read only on READY, its count capped before any slice exists, and its fault
/// named for its op.
#[test]
fn check_answer_reads_a_leased_list_only_on_ready() {
    use crate::abi::store::slot;
    use std::mem::size_of;
    // SAFETY: as above.
    let input: crate::abi::mechanism::call::InHead = unsafe { std::mem::zeroed() };
    let hs = size_of::<crate::abi::mechanism::call::InHead>();
    let list = LeasedListOut {
        head: head(),
        items: null(),
        items_len: LIST_ITEMS_HARD_MAX as usize + 1,
    };
    let ls = size_of::<LeasedListOut>();
    assert_eq!(
        answer(slot::LIST_AUDIT, R, &input, hs, &list, ls),
        Err(fault(Rule::OverCap, "list_audit.items"))
    );
    assert_eq!(
        answer(slot::LIST_KEYS_SINCE, R, &input, hs, &list, ls),
        Err(fault(Rule::OverCap, "list_keys_since.items"))
    );
    // FAILED holds no lease: nothing is read, and the validator states nothing for it.
    assert_eq!(answer(slot::LIST_AUDIT, F, &input, hs, &list, ls), Ok(()));
}
