// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store kind adapter: every checked op answers GREEN and RED through its `abi/store/check.rs`
//! validator, a plugin count above the host's cap is FAULT before any slice exists, and every
//! store slot has a name.

use std::mem::{size_of, size_of_val};
use std::ptr::{null, NonNull};

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::check::{Fault, Rule};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelOut, LIFECYCLE_SLOTS};
use busbar_contract::abi::store::check::{self as sc, LIST_ITEMS_HARD_MAX};
use busbar_contract::abi::store::{
    slot, CellGrant, CountOut, HeadOut, HostBlobs, HostBuf, HostBytesOut, HostListOut,
    LeasedListOut, ListPlaneRecordsIn, OpId, RecordGetIn, ReleaseItem, ReserveIn, ReserveOut,
    SliceReleaseIn, SliceReleaseOut, UnitCell, VerdictOut, WindowCapsIn, FOUND, KIND_SLOTS, NAMES,
    OPS, RESERVE_EXHAUSTED, RESERVE_NO_FAILED_CELL, RESERVE_OK,
};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{in_head, out_head, Answer, InFrame, Kind, OutFrame, NO_BLOB};

const NO_STR: AbiStr = AbiStr {
    ptr: null(),
    len: 0,
};

fn answer<I: InFrame, O: OutFrame>(s: u32, outcome: Outcome, i: &I, o: &O) -> Answer<'static> {
    // SAFETY: `i`/`o` outlive every use of the answer in the test that built it.
    unsafe {
        Answer::new(
            s,
            outcome,
            (i as *const I).cast(),
            size_of::<I>(),
            (o as *const O).cast(),
            size_of::<O>(),
        )
    }
}

fn rule(r: Result<(), Fault>) -> Rule {
    r.expect_err("the answer must FAULT").rule
}

fn cell(amount: u64) -> UnitCell {
    UnitCell {
        bucket: NO_STR,
        pool: NO_STR,
        dimension: 0,
        _r: 0,
        class_key: NO_STR,
        amount,
        window_start: 0,
    }
}

fn grant(granted: u64) -> CellGrant {
    CellGrant {
        slice_id: 1,
        granted,
        valid_until_ms: 0,
    }
}

fn reserve_in(cells: &[UnitCell], grants: *mut CellGrant, grants_cap: usize) -> ReserveIn {
    ReserveIn {
        head: in_head(),
        op_id: OpId([0; 16]),
        epoch: 1,
        cells: cells.as_ptr(),
        cells_len: cells.len(),
        grants,
        grants_cap,
    }
}

fn reserve_out(grants_len: usize, reason: u32, needed_grants: u64) -> ReserveOut {
    ReserveOut {
        head: out_head(),
        grants_len,
        reason,
        failed_cell: RESERVE_NO_FAILED_CELL,
        needed_grants,
    }
}

// ── reserve ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn reserve_green_whole_grants() {
    let cells = [cell(5), cell(7)];
    let mut grants = [grant(5), grant(7)];
    let i = reserve_in(&cells, grants.as_mut_ptr(), 2);
    let o = reserve_out(2, RESERVE_OK, 0);
    assert_eq!(
        Store::check(&answer(slot::RESERVE, Outcome::Ready, &i, &o)),
        Ok(())
    );
    let o = reserve_out(0, RESERVE_EXHAUSTED, 0);
    assert_eq!(
        Store::check(&answer(slot::RESERVE, Outcome::Failed, &i, &o)),
        Ok(())
    );
}

#[test]
fn reserve_red_partial_grant() {
    let cells = [cell(5), cell(7)];
    let mut grants = [grant(5), grant(6)];
    let i = reserve_in(&cells, grants.as_mut_ptr(), 2);
    let o = reserve_out(2, RESERVE_OK, 0);
    let f = Store::check(&answer(slot::RESERVE, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(f, sc::GRANT_OUT_OF_RANGE);
}

#[test]
fn reserve_grants_len_over_cap_faults_before_any_slice() {
    let cells = [cell(5), cell(7)];
    // A dangling pointer: never read, because the count is refused first.
    let i = reserve_in(&cells, NonNull::<CellGrant>::dangling().as_ptr(), 2);
    let o = reserve_out(3, RESERVE_OK, 0);
    let f = Store::check(&answer(slot::RESERVE, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(f.rule, Rule::OverCap);
    assert_eq!(f.field, "reserve.grants");
}

#[test]
fn reserve_in_too_small_is_foreign() {
    let i = in_head();
    let o = reserve_out(0, RESERVE_OK, 0);
    assert_eq!(
        rule(Store::check(&answer(slot::RESERVE, Outcome::Ready, &i, &o))),
        Rule::Foreign
    );
}

#[test]
fn reserve_short_is_short_and_checks() {
    let cells = [cell(5), cell(7), cell(9)];
    let mut grants = [grant(0), grant(0)];
    let i = reserve_in(&cells, grants.as_mut_ptr(), 2);
    let o = reserve_out(0, RESERVE_OK, 3);
    let a = answer(slot::RESERVE, Outcome::Failed, &i, &o);
    assert_eq!(Store::check(&a), Ok(()));
    assert!(Store::short(&a));
    // A needed count the cap already covers wastes the re-call.
    let o = reserve_out(0, RESERVE_OK, 2);
    let a = answer(slot::RESERVE, Outcome::Failed, &i, &o);
    assert_eq!(rule(Store::check(&a)), Rule::WastedRecall);
    // Never short on another outcome.
    let o = reserve_out(0, RESERVE_OK, 3);
    assert!(!Store::short(&answer(
        slot::RESERVE,
        Outcome::Refused,
        &i,
        &o
    )));
    let o = reserve_out(0, RESERVE_EXHAUSTED, 0);
    assert!(!Store::short(&answer(
        slot::RESERVE,
        Outcome::Failed,
        &i,
        &o
    )));
}

// ── slice_release ────────────────────────────────────────────────────────────────────────────

fn release_in(items: &[ReleaseItem], released: &mut [u64]) -> SliceReleaseIn {
    SliceReleaseIn {
        head: in_head(),
        op_id: OpId([0; 16]),
        epoch: 1,
        items: items.as_ptr(),
        items_len: items.len(),
        released: released.as_mut_ptr(),
        released_cap: released.len(),
    }
}

fn release_out(released_len: usize) -> SliceReleaseOut {
    SliceReleaseOut {
        head: out_head(),
        released_len,
        needed_released: 0,
    }
}

#[test]
fn slice_release_green_and_red() {
    let items = [
        ReleaseItem {
            slice_id: 1,
            unspent: 10,
        },
        ReleaseItem {
            slice_id: 2,
            unspent: 4,
        },
    ];
    let mut released = [10, 3];
    let i = release_in(&items, &mut released);
    let o = release_out(2);
    assert_eq!(
        Store::check(&answer(slot::SLICE_RELEASE, Outcome::Ready, &i, &o)),
        Ok(())
    );

    let mut released = [10, 5];
    let i = release_in(&items, &mut released);
    let f = Store::check(&answer(slot::SLICE_RELEASE, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(f, sc::RELEASE_OVER_UNSPENT);

    let mut released = [0u64; 2];
    let mut i = release_in(&items, &mut released);
    i.released = NonNull::<u64>::dangling().as_ptr();
    let o = release_out(3);
    let f = Store::check(&answer(slot::SLICE_RELEASE, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!((f.rule, f.field), (Rule::OverCap, "slice_release.released"));
}

// ── record_get ───────────────────────────────────────────────────────────────────────────────

fn record_get_in(buf: &mut [u8]) -> RecordGetIn {
    RecordGetIn {
        head: in_head(),
        schema: NO_STR,
        key: NO_BLOB,
        value: HostBuf {
            ptr: buf.as_mut_ptr(),
            cap: buf.len(),
        },
    }
}

fn bytes_out(written: u64, needed: u64) -> HostBytesOut {
    HostBytesOut {
        head: out_head(),
        found: FOUND,
        _reserved: 0,
        written,
        needed,
    }
}

#[test]
fn record_get_green_red_and_short() {
    let mut buf = [0u8; 16];
    let i = record_get_in(&mut buf);
    let o = bytes_out(10, 0);
    assert_eq!(
        Store::check(&answer(slot::RECORD_GET, Outcome::Ready, &i, &o)),
        Ok(())
    );

    let o = bytes_out(17, 0);
    let f = Store::check(&answer(slot::RECORD_GET, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(f, sc::COUNT_OVER_CAP);

    let mut o = bytes_out(0, 0);
    o.found = 7;
    assert_eq!(
        rule(Store::check(&answer(
            slot::RECORD_GET,
            Outcome::Ready,
            &i,
            &o
        ))),
        Rule::UnknownCode
    );

    let o = bytes_out(0, 32);
    let a = answer(slot::RECORD_GET, Outcome::Failed, &i, &o);
    assert_eq!(Store::check(&a), Ok(()));
    assert!(Store::short(&a));
    let a = answer(slot::RECORD_GET, Outcome::Ready, &i, &o);
    assert_eq!(rule(Store::check(&a)), Rule::NeededNotFailed);
}

// ── list_plane_records (a host list) ─────────────────────────────────────────────────────────

fn list_in(items: &mut [Blob], bytes: &mut [u8]) -> ListPlaneRecordsIn {
    ListPlaneRecordsIn {
        head: in_head(),
        kind: NO_STR,
        selector: 0,
        _reserved: 0,
        parent: NO_STR,
        out: HostBlobs {
            items: items.as_mut_ptr(),
            items_cap: items.len(),
            bytes: HostBuf {
                ptr: bytes.as_mut_ptr(),
                cap: bytes.len(),
            },
        },
    }
}

fn list_out(items_written: u64, bytes_written: u64) -> HostListOut {
    HostListOut {
        head: out_head(),
        items_written,
        bytes_written,
        needed_items: 0,
        needed_bytes: 0,
    }
}

fn blob_at(ptr: *const u8, len: usize) -> Blob {
    Blob {
        ptr,
        len,
        fmt: BLOB_JSON,
        flags: 0,
    }
}

#[test]
fn list_plane_records_green_and_red() {
    let mut bytes = [0u8; 16];
    let base = bytes.as_ptr();
    let mut items = [blob_at(base, 4), NO_BLOB];
    let i = list_in(&mut items, &mut bytes);
    let o = list_out(1, 4);
    assert_eq!(
        Store::check(&answer(slot::LIST_PLANE_RECORDS, Outcome::Ready, &i, &o)),
        Ok(())
    );

    // A blob past the written bytes.
    let mut items = [blob_at(base.wrapping_add(2), 4), NO_BLOB];
    let i = list_in(&mut items, &mut bytes);
    let f = Store::check(&answer(slot::LIST_PLANE_RECORDS, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(f, sc::SPAN_OUT_OF_BOUNDS);
}

#[test]
fn list_plane_records_items_over_cap_faults_before_any_slice() {
    let mut bytes = [0u8; 16];
    let mut items = [NO_BLOB];
    let mut i = list_in(&mut items, &mut bytes);
    i.out.items = NonNull::<Blob>::dangling().as_ptr();
    let o = list_out(2, 0);
    let f = Store::check(&answer(slot::LIST_PLANE_RECORDS, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(
        (f.rule, f.field),
        (Rule::OverCap, "list_plane_records.items")
    );
}

#[test]
fn list_plane_records_short() {
    let mut bytes = [0u8; 16];
    let mut items = [NO_BLOB];
    let i = list_in(&mut items, &mut bytes);
    let mut o = list_out(0, 0);
    o.needed_items = 1;
    o.needed_bytes = 64;
    let a = answer(slot::LIST_PLANE_RECORDS, Outcome::Failed, &i, &o);
    assert_eq!(Store::check(&a), Ok(()));
    assert!(Store::short(&a));
}

// ── a leased list ────────────────────────────────────────────────────────────────────────────

fn leased(items: *const Blob, items_len: usize) -> LeasedListOut {
    LeasedListOut {
        head: out_head(),
        items,
        items_len,
    }
}

#[test]
fn leased_list_green_and_red() {
    let body = b"{}";
    let items = [blob_at(body.as_ptr(), body.len())];
    let i = in_head();
    let o = leased(items.as_ptr(), 1);
    assert_eq!(
        Store::check(&answer(slot::LIST_KEYS, Outcome::Ready, &i, &o)),
        Ok(())
    );

    // A record with a length but no bytes.
    let items = [blob_at(null(), 3)];
    let o = leased(items.as_ptr(), 1);
    let f = Store::check(&answer(slot::LIST_KEYS, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(f, sc::NULL_WITH_COUNT);

    // A count with a NULL array.
    let o = leased(null(), 1);
    let f = Store::check(&answer(slot::LIST_AUDIT, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!((f.rule, f.field), (Rule::NullWithCount, "list_audit.items"));

    // Above the hard maximum: refused before the dangling array is sliced.
    let o = leased(
        NonNull::dangling().as_ptr(),
        LIST_ITEMS_HARD_MAX as usize + 1,
    );
    let f = Store::check(&answer(slot::LIST_METERING, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!((f.rule, f.field), (Rule::OverCap, "list_metering.items"));

    // No lease on FAILED: nothing is read.
    assert_eq!(
        Store::check(&answer(slot::LIST_METERING, Outcome::Failed, &i, &o)),
        Ok(())
    );
}

// ── verdict, cancel, window_caps ─────────────────────────────────────────────────────────────

#[test]
fn verdict_green_and_red() {
    let i = in_head();
    for (v, ok) in [(0, true), (1, true), (2, false)] {
        let o = VerdictOut {
            head: out_head(),
            verdict: v,
            _reserved: 0,
        };
        let r = Store::check(&answer(slot::REDEEM_PLANE_TOKEN, Outcome::Ready, &i, &o));
        assert_eq!(r.is_ok(), ok, "verdict {v}");
        let r = Store::check(&answer(slot::PLANE_TOKEN_LIVE, Outcome::Ready, &i, &o));
        assert_eq!(r.is_ok(), ok, "verdict {v}");
    }
}

#[test]
fn cancel_green_and_red() {
    let i = in_head();
    for (d, ok) in [(0, true), (1, true), (2, true), (3, false)] {
        let o = CancelOut {
            head: out_head(),
            disposition: d,
            _reserved: 0,
        };
        let r = Store::check(&answer(life::CANCEL, Outcome::Ready, &i, &o));
        assert_eq!(r.is_ok(), ok, "disposition {d}");
        if !ok {
            assert_eq!(r.unwrap_err(), sc::VOCABULARY);
        }
    }
}

fn window_caps_error(i: &WindowCapsIn, outcome: Outcome, text: &[u8]) -> Result<(), Fault> {
    let mut o = out_head();
    o.error = AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    };
    Store::check(&answer(slot::WINDOW_CAPS, outcome, i, &o))
}

#[test]
fn window_caps_refused_error_text_is_checked() {
    let i = WindowCapsIn {
        head: in_head(),
        op_id: OpId([0; 16]),
        caps: null(),
        caps_len: 3,
    };
    assert_eq!(
        window_caps_error(&i, Outcome::Refused, b"2: STORE_CAP_CONFLICT"),
        Ok(())
    );
    // A REFUSED push whose text names no cap, or a cap outside the push.
    assert_eq!(
        window_caps_error(&i, Outcome::Refused, b"STORE_CAP_CONFLICT"),
        Err(sc::MISSING)
    );
    assert_eq!(
        window_caps_error(&i, Outcome::Refused, b"3: STORE_CAP_CONFLICT"),
        Err(sc::COUNT_OVER_CAP)
    );
    // A REFUSED push with no text at all.
    let o = out_head();
    assert_eq!(
        Store::check(&answer(slot::WINDOW_CAPS, Outcome::Refused, &i, &o)),
        Err(sc::MISSING)
    );
    // The same text on another outcome is not a refusal's index.
    assert_eq!(
        window_caps_error(&i, Outcome::Failed, b"STORE_CAP_CONFLICT"),
        Ok(())
    );
}

#[test]
fn window_caps_green_and_red() {
    let mut i = WindowCapsIn {
        head: in_head(),
        op_id: OpId([0; 16]),
        caps: null(),
        caps_len: 0,
    };
    let o = out_head();
    assert_eq!(
        Store::check(&answer(slot::WINDOW_CAPS, Outcome::Ready, &i, &o)),
        Ok(())
    );
    i.caps_len = LIST_ITEMS_HARD_MAX as usize + 1;
    let f = Store::check(&answer(slot::WINDOW_CAPS, Outcome::Ready, &i, &o)).unwrap_err();
    assert_eq!(f, sc::COUNT_OVER_CAP);
}

// ── purges and append_batch ──────────────────────────────────────────────────────────────────

#[test]
fn purges_route_to_the_count_check() {
    let i = in_head();
    for s in [
        slot::PURGE_WINDOWS_BEFORE,
        slot::PURGE_METERING_BEFORE,
        slot::PURGE_PLANE_RECORDS_BEFORE,
    ] {
        let o = CountOut {
            head: out_head(),
            count: 9,
        };
        assert_eq!(Store::check(&answer(s, Outcome::Ready, &i, &o)), Ok(()));
        assert_eq!(
            Store::check(&answer(s, Outcome::Failed, &i, &o)),
            Err(sc::WRITTEN_ON_FAILED),
            "{}",
            Store::op_name(s)
        );
    }
}

#[test]
fn append_batch_routes_to_the_head_check() {
    let i = in_head();
    let o = HeadOut {
        head: out_head(),
        seq: 41,
        epoch: 3,
    };
    assert_eq!(
        Store::check(&answer(slot::APPEND_BATCH, Outcome::Ready, &i, &o)),
        Ok(())
    );
    assert_eq!(
        Store::check(&answer(slot::APPEND_BATCH, Outcome::Failed, &i, &o)),
        Err(sc::WRITTEN_ON_FAILED)
    );
    // Too small an `out` for a head is a foreign struct.
    let o = out_head();
    assert_eq!(
        rule(Store::check(&answer(
            slot::APPEND_BATCH,
            Outcome::Ready,
            &i,
            &o
        ))),
        Rule::Foreign
    );
}

// ── every outcome ────────────────────────────────────────────────────────────────────────────

/// Every store slot, and `cancel`, answered PENDING or REFUSED with a zeroed `in` and `out` of
/// the slot's own sizes passes its check; the one rule about those outcomes that a zeroed `out`
/// breaks is `window_caps`' REFUSED error text.
#[test]
fn a_zeroed_answer_on_pending_or_refused_passes_every_slot() {
    let zero_in = [0u64; 128];
    let zero_out = [0u64; 128];
    let mut slots: Vec<(u32, usize, usize)> =
        OPS.iter().map(|c| (c.slot, c.max_in, c.max_out)).collect();
    slots.push((life::CANCEL, size_of::<InHead>(), size_of::<CancelOut>()));
    for (s, in_size, out_size) in slots {
        assert!(in_size <= size_of_val(&zero_in) && out_size <= size_of_val(&zero_out));
        for outcome in [Outcome::Pending, Outcome::Refused] {
            // SAFETY: both buffers outlive the answer and hold at least the slot's sizes.
            let a = unsafe {
                Answer::new(
                    s,
                    outcome,
                    zero_in.as_ptr().cast(),
                    in_size,
                    zero_out.as_ptr().cast(),
                    out_size,
                )
            };
            let r = Store::check(&a);
            if s == slot::WINDOW_CAPS && outcome == Outcome::Refused {
                assert_eq!(r, Err(sc::MISSING));
            } else {
                assert_eq!(r, Ok(()), "{} {outcome:?}", Store::op_name(s));
            }
        }
    }
}

// ── unchecked ops, names, faults ─────────────────────────────────────────────────────────────

#[test]
fn unchecked_op_answers_ok() {
    let i = in_head();
    let o = out_head();
    assert_eq!(
        Store::check(&answer(slot::PUT_KEY, Outcome::Ready, &i, &o)),
        Ok(())
    );
    assert!(!Store::short(&answer(
        slot::PUT_KEY,
        Outcome::Failed,
        &i,
        &o
    )));
}

#[test]
fn every_store_slot_is_named() {
    for k in 0..KIND_SLOTS {
        let s = LIFECYCLE_SLOTS + k;
        let name = Store::op_name(s);
        assert_ne!(name, "op", "slot {s}");
        assert_eq!(name, NAMES[k as usize]);
    }
    assert_eq!(Store::op_name(slot::RESERVE), "reserve");
    assert_eq!(Store::op_name(slot::WINDOW_CAPS), "window_caps");
    assert_eq!(Store::op_name(life::CANCEL), "cancel");
    assert_eq!(Store::op_name(LIFECYCLE_SLOTS + KIND_SLOTS), "op");
}

#[test]
fn every_store_fault_maps_to_a_distinct_field() {
    let all = [
        sc::VOCABULARY,
        sc::NEEDED_NOT_FAILED,
        sc::NEEDED_TOO_LARGE,
        sc::NEEDED_WITHIN_CAP,
        sc::WRITTEN_ON_FAILED,
        sc::COUNT_OVER_CAP,
        sc::COUNT_MISMATCH,
        sc::NULL_WITH_COUNT,
        sc::ABSENT_WITH_LEN,
        sc::SPAN_OUT_OF_BOUNDS,
        sc::GRANT_OUT_OF_RANGE,
        sc::RELEASE_OVER_UNSPENT,
        sc::FAILED_CELL_OUT_OF_RANGE,
        sc::MISSING,
    ];
    let mut fields: Vec<&str> = all.iter().map(|f| f.field).collect();
    fields.sort_unstable();
    fields.dedup();
    assert_eq!(fields.len(), all.len());
}

#[test]
fn out_too_small_is_foreign() {
    let i = in_head();
    let o = out_head();
    assert_eq!(
        rule(Store::check(&answer(
            slot::REDEEM_PLANE_TOKEN,
            Outcome::Ready,
            &i,
            &o
        ))),
        Rule::Foreign
    );
}
