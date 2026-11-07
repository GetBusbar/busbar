// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The canonical primitive Store ABI3 table, its mandatory slots and safe values.

use std::mem::{offset_of, size_of};

use busbar_contract::abi::mechanism::call::{DeadlineClass, InHead};
use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
use busbar_contract::abi::store::v4::{
    self as store, slot, Ops, KIND_SLOTS, NAMES, OPS, TABLE_SLOTS,
};
use busbar_contract::records::OpId;

#[test]
fn every_kind_slot_is_lifecycle_slots_plus_k_contiguous() {
    assert_eq!(KIND_SLOTS, 5);
    assert_eq!(TABLE_SLOTS, 14);
    assert_eq!(slot::BOOTSTRAP, 13);
    assert_eq!(OPS.len() as u32, KIND_SLOTS);
    assert_eq!(TABLE_SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
    for (k, c) in OPS.iter().enumerate() {
        assert_eq!(c.slot, LIFECYCLE_SLOTS + k as u32, "{}", NAMES[k]);
    }

    assert_eq!(offset_of!(Ops, read), size_of::<OpsHead>());
    assert_eq!(
        offset_of!(Ops, bootstrap),
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
    assert_eq!(NAMES, ["read", "scan", "commit", "clock", "bootstrap"]);
    assert_eq!(slot::BOOTSTRAP - slot::READ + 1, 5);
}

#[test]
fn every_slot_states_its_contract() {
    for (c, name) in OPS.iter().zip(NAMES) {
        assert!(c.may_pend, "{name}: network stores pend on driver tickets");
        assert!(c.max_in >= size_of::<InHead>(), "{name}");
    }
    for contract in OPS {
        assert_eq!(contract.deadline, DeadlineClass::Call);
    }
    assert_eq!(OPS[0].max_in, size_of::<store::ReadIn>());
    assert_eq!(OPS[1].max_in, size_of::<store::ScanIn>());
    assert_eq!(OPS[2].max_in, size_of::<store::CommitIn>());
    assert_eq!(OPS[3].max_in, size_of::<store::ClockIn>());
    assert_eq!(OPS[4].max_in, size_of::<store::BootstrapIn>());
    assert_eq!(OPS[4].max_out, size_of::<store::BootstrapOut>());
    assert!(!OPS[4].request_path);
}

#[test]
fn every_primitive_request_and_response_starts_with_the_shared_head() {
    assert_eq!(offset_of!(store::ReadIn, head), 0);
    assert_eq!(offset_of!(store::ScanIn, head), 0);
    assert_eq!(offset_of!(store::CommitIn, head), 0);
    assert_eq!(offset_of!(store::ClockIn, head), 0);
    assert_eq!(offset_of!(store::ReadOut, head), 0);
    assert_eq!(offset_of!(store::ScanOut, head), 0);
    assert_eq!(offset_of!(store::CommitOut, head), 0);
    assert_eq!(offset_of!(store::ClockOut, head), 0);
    assert_eq!(offset_of!(store::BootstrapIn, head), 0);
    assert_eq!(offset_of!(store::BootstrapOut, head), 0);
    assert_eq!(offset_of!(store::CommitIn, candidate), size_of::<InHead>());
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
    assert_eq!(store::VALUE_ABSENT, 0);
    assert_ne!(store::COMMIT_APPLIED, 0);
    assert_ne!(store::READ_VALUES, 0);
    assert_ne!(store::SCAN_PAGE, 0);
    assert_eq!(busbar_contract::abi::store::CANCEL_UNKNOWN, 0);
    assert_eq!(
        busbar_contract::abi::store::DIAG_OPID_CONFLICT,
        "STORE_OPID_CONFLICT"
    );
    const { assert!(busbar_contract::abi::store::OP_ID_RETENTION_SECS >= 24 * 60 * 60) };
}
