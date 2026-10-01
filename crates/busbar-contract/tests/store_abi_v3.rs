// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S v3 TABLE, AS STATED (B.1 "store (v3)"; m3-inputs "store v3 money slots" and
//! "window caps"): the slot numbering, the per-slot contract and the zero readings the money
//! shapes depend on. Layout is pinned once, by the golden (`layout_golden.rs`).

use std::mem::{offset_of, size_of};

use busbar_contract::abi::mechanism::call::{DeadlineClass, InHead};
use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
use busbar_contract::abi::store::{self, slot, OpId, Ops, KIND_SLOTS, NAMES, OPS, TABLE_SLOTS};

#[test]
fn every_kind_slot_is_lifecycle_slots_plus_k_contiguous() {
    assert_eq!(OPS.len() as u32, KIND_SLOTS);
    assert_eq!(TABLE_SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
    for (k, c) in OPS.iter().enumerate() {
        assert_eq!(c.slot, LIFECYCLE_SLOTS + k as u32, "{}", NAMES[k]);
    }
    // The table: the head, then one pointer per slot, the first right after the head.
    assert_eq!(offset_of!(Ops, put_key), size_of::<OpsHead>());
    assert_eq!(
        offset_of!(Ops, window_caps),
        size_of::<OpsHead>() + 8 * (KIND_SLOTS as usize - 1)
    );
    assert_eq!(
        size_of::<Ops>(),
        size_of::<OpsHead>() + 8 * KIND_SLOTS as usize
    );
    let mut names = NAMES.to_vec();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), OPS.len(), "slot names are unique");
}

#[test]
fn the_design_names_every_slot() {
    // B.1: the ten 1.6.0 ledger ops, the three batch slots, the cap input.
    for name in [
        "append_batch",
        "reserve",
        "slice_release",
        "heads",
        "session_put",
        "session_remove",
        "sessions_for",
        "record_put",
        "record_get",
        "record_scan",
        "add_usage_batch",
        "add_metering_batch",
        "append_audit_batch",
        "window_caps",
        // plane records (records.rs:1481-1597)
        "upsert_plane_record",
        "get_plane_record",
        "append_plane_record",
        "list_plane_records",
        "list_plane_record_parents",
        "purge_plane_records_before",
        "delete_plane_record",
        "redeem_plane_token",
        "plane_token_live",
    ] {
        assert!(NAMES.contains(&name), "{name}");
    }
    // The full 1.5.5 op set: 24 methods, first in the table.
    assert_eq!(slot::LIST_AUDIT_TAIL - slot::PUT_KEY + 1, 24);
}

#[test]
fn every_slot_states_its_contract() {
    for (c, name) in OPS.iter().zip(NAMES) {
        assert!(c.may_pend, "{name}: network stores pend on driver tickets");
        assert!(c.max_in >= size_of::<InHead>(), "{name}");
    }
    let of = |name: &str| OPS[NAMES.iter().position(|n| *n == name).unwrap()];
    // m3-inputs "store v3 money slots": reserve and slice_release are request path, Call.
    for name in ["reserve", "slice_release"] {
        assert!(of(name).request_path, "{name}");
        assert_eq!(of(name).deadline, DeadlineClass::Call, "{name}");
    }
    // B.1 "Writes": every additive or appending write is write_behind.
    for name in [
        "add_usage",
        "add_metering",
        "append_audit",
        "append_plane_record",
        "append_batch",
        "add_usage_batch",
        "add_metering_batch",
        "append_audit_batch",
    ] {
        assert_eq!(of(name).deadline, DeadlineClass::WriteBehind, "{name}");
    }
    assert_eq!(of("reserve").max_in, size_of::<store::ReserveIn>());
    assert_eq!(of("reserve").max_out, size_of::<store::ReserveOut>());
}

#[test]
fn every_op_id_slot_carries_it_right_after_the_head() {
    // The dedupe key sits at one offset on every slot that carries one.
    let at = size_of::<InHead>();
    assert_eq!(offset_of!(store::ReserveIn, op_id), at);
    assert_eq!(offset_of!(store::SliceReleaseIn, op_id), at);
    assert_eq!(offset_of!(store::AddUsageBatchIn, op_id), at);
    assert_eq!(offset_of!(store::OpBlobsIn, op_id), at);
    assert_eq!(offset_of!(store::WindowCapsIn, op_id), at);
    assert_eq!(offset_of!(store::AddUsageIn, op_id), at);
    assert_eq!(offset_of!(store::OpBlobIn, op_id), at);
    assert_eq!(offset_of!(store::AppendPlaneRecordIn, op_id), at);
    assert_eq!(offset_of!(store::AppendBatchIn, op_id), at);
}

#[test]
fn an_op_id_is_node_then_counter() {
    let id = OpId::from_parts(0x0102_0304_0506_0708, 42);
    assert_eq!(id.node(), 0x0102_0304_0506_0708);
    assert_eq!(id.counter(), 42);
    assert_eq!(id.0[0], 0x08);
    assert_eq!(id.0[8], 42);
    assert_ne!(OpId::from_parts(1, 2), OpId::from_parts(2, 1));
}

#[test]
fn the_zero_readings_are_the_safe_ones() {
    // m3-inputs "store v3 money slots": reasons 1 Exhausted / 2 StaleEpoch / 3 Unavailable;
    // "window caps": 4 NoCap.
    assert_eq!(store::RESERVE_OK, 0);
    assert_eq!(store::RESERVE_EXHAUSTED, 1);
    assert_eq!(store::RESERVE_STALE_EPOCH, 2);
    assert_eq!(store::RESERVE_UNAVAILABLE, 3);
    assert_eq!(store::RESERVE_NO_CAP, 4);
    // "window caps" correction (3): no failed cell is u32::MAX.
    assert_eq!(store::RESERVE_NO_FAILED_CELL, u32::MAX);
    // Dimensions: 0 NanoUnits, 1 Requests, 2 Concurrency, 3 Class.
    assert_eq!(
        [
            store::DIM_NANO_UNITS,
            store::DIM_REQUESTS,
            store::DIM_CONCURRENCY,
            store::DIM_CLASS
        ],
        [0, 1, 2, 3]
    );
    // An unwritten out never reads as a record, a YES or a settled cancel.
    assert_eq!(store::ABSENT, 0);
    assert_eq!(store::VERDICT_NO, 0);
    assert_eq!(store::CANCEL_UNKNOWN, 0);
    assert_eq!(store::DISPOSITION_ACTIVE, 0);
    assert_eq!(store::DIAG_OPID_CONFLICT, "STORE_OPID_CONFLICT");
    assert_eq!(store::DIAG_CAP_CONFLICT, "STORE_CAP_CONFLICT");
    const { assert!(store::OP_ID_RETENTION_SECS >= 24 * 60 * 60) };
}
