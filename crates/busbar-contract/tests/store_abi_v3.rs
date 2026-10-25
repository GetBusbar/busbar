// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S v3 TABLE, AS STATED: the slot numbering, the per-slot contract and the zero
//! readings. Layout is pinned once, by the golden (`layout_golden.rs`).

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
        offset_of!(Ops, add_metering_batch),
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
    // The kernel-held records and the two count batches.
    for name in [
        "record_put",
        "record_get",
        "record_scan",
        "add_usage_batch",
        "add_metering_batch",
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
    // The kept 1.5.5 op set comes first in the table.
    assert_eq!(slot::LIST_AUDIT_TAIL - slot::PUT_KEY + 1, 17);
}

#[test]
fn every_slot_states_its_contract() {
    for (c, name) in OPS.iter().zip(NAMES) {
        assert!(c.may_pend, "{name}: network stores pend on driver tickets");
        assert!(c.max_in >= size_of::<InHead>(), "{name}");
    }
    let of = |name: &str| OPS[NAMES.iter().position(|n| *n == name).unwrap()];
    // Every additive or appending write is write_behind.
    for name in [
        "append_plane_record",
        "add_usage_batch",
        "add_metering_batch",
    ] {
        assert_eq!(of(name).deadline, DeadlineClass::WriteBehind, "{name}");
    }
    assert_eq!(
        of("add_usage_batch").max_in,
        size_of::<store::AddUsageBatchIn>()
    );
}

#[test]
fn every_op_id_slot_carries_it_right_after_the_head() {
    // The dedupe key sits at one offset on every slot that carries one.
    let at = size_of::<InHead>();
    assert_eq!(offset_of!(store::AddUsageBatchIn, op_id), at);
    assert_eq!(offset_of!(store::OpBlobsIn, op_id), at);
    assert_eq!(offset_of!(store::AppendPlaneRecordIn, op_id), at);
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
    // An unwritten out never reads as a record, a YES or a settled cancel.
    assert_eq!(store::ABSENT, 0);
    assert_eq!(store::VERDICT_NO, 0);
    assert_eq!(store::CANCEL_UNKNOWN, 0);
    assert_eq!(store::DISPOSITION_ACTIVE, 0);
    assert_eq!(store::DIAG_OPID_CONFLICT, "STORE_OPID_CONFLICT");
    const { assert!(store::OP_ID_RETENTION_SECS >= 24 * 60 * 60) };
}
