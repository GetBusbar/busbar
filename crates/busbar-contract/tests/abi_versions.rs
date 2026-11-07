// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pin ABI counters to one increment from released v1.5.5; new kinds start at one.

use std::os::raw::c_void;

use busbar_contract::abi::mechanism::call::{Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::{auth, export, hook, plane, secret, store, transport};

#[test]
fn current_abi_generations_are_explicit() {
    assert_eq!(busbar_contract::abi::ABI_MAJOR, 1);
    assert_eq!(busbar_contract::abi::ABI_MINOR, 0);
    assert_eq!(MECHANISM_VERSION, 2);
    assert_eq!(store::ABI_VERSION, 3);
    assert_eq!(secret::ABI_VERSION, 2);
    assert_eq!(auth::ABI_VERSION, 3);
    assert_eq!(hook::ABI_VERSION, 2);
    assert_eq!(export::ABI_VERSION, 3);
    // Plane and Transport are new kinds since v1.5.5.
    assert_eq!(plane::ABI_VERSION, 1);
    assert_eq!(transport::ABI_VERSION, 1);
    assert_eq!(store::v4::ABI_VERSION, 3);
    assert_ne!(store::v4::LAYOUT_FINGERPRINT, store::LAYOUT_FINGERPRINT);
}

#[test]
fn a_kind_code_names_its_own_version_and_nothing_else() {
    let want = [
        (1, store::ABI_VERSION),
        (2, secret::ABI_VERSION),
        (3, auth::ABI_VERSION),
        (4, hook::ABI_VERSION),
        (5, export::ABI_VERSION),
        (6, plane::ABI_VERSION),
        (7, transport::ABI_VERSION),
    ];
    for (k, (raw, v)) in KindCode::ALL.iter().zip(want) {
        assert_eq!(*k as u32, raw);
        assert_eq!(KindCode::from_raw(raw), Some(*k));
        assert_eq!(k.abi_version(), v);
    }
    assert_eq!(KindCode::from_raw(0), None);
    assert_eq!(KindCode::from_raw(8), None);
}

#[test]
fn the_door_is_found_by_one_symbol_and_one_magic() {
    assert_eq!(DOOR_SYMBOL, b"busbar_plugin_door\0");
    assert_eq!(&DOOR_MAGIC.to_le_bytes(), b"BUSBARPL");

    assert_ne!(DOOR_MAGIC, busbar_contract::abi::ABI_MAGIC);
}

#[test]
fn an_unwritten_out_reads_as_a_fault() {
    assert_eq!(RawOutcome(0).outcome(), Outcome::Fault);
    assert_eq!(RawOutcome(200).outcome(), Outcome::Fault);
    for o in [
        Outcome::Fault,
        Outcome::Ready,
        Outcome::Pending,
        Outcome::Failed,
        Outcome::Refused,
    ] {
        assert_eq!(RawOutcome::of(o).outcome(), o);
    }
    assert!(Ticket::NONE.is_none());
}

extern "C" fn an_op(_i: *mut c_void, _in: *const c_void, _out: *mut c_void) -> RawOutcome {
    RawOutcome::of(Outcome::Ready)
}
extern "C" fn a_door() -> *const Door {
    std::ptr::null()
}
extern "C" fn a_sealed_door() -> &'static Door {
    static_door::door()
}
mod static_door {
    struct Life;
    impl busbar_contract::abi::sdk::life::Life for Life {
        const CANCEL: u32 = 0;
        fn open(
            _: &[u8],
            _: &[&[u8]],
            _: u64,
        ) -> Result<Self, busbar_contract::abi::sdk::life::Refusal> {
            Ok(Life)
        }
        fn refresh(
            &self,
            _: &[u8],
            _: &[&[u8]],
            _: u64,
        ) -> Result<
            busbar_contract::abi::sdk::life::Refreshed,
            busbar_contract::abi::sdk::life::Refusal,
        > {
            Ok(busbar_contract::abi::sdk::life::Refreshed::default())
        }
    }
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement("a-door", "0", 1),
        lifecycle: life(Life),
    }
}
extern "C" fn a_wake(_c: HostCtx, _t: Ticket) {}

#[test]
fn every_slot_type_is_extern_c() {
    let op: Op = an_op;
    let raw: RawDoorFn = a_door;
    let door: DoorFn = a_sealed_door;
    let wake: WakeFn = a_wake;
    assert_eq!(
        // SAFETY: this exact fixture slot ignores all three pointers, accepting NULL without
        // reading input or output; no general plugin slot is entered with these pointers.
        unsafe { op(std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut()) }.outcome(),
        Outcome::Ready
    );
    assert!(raw().is_null());
    assert_eq!(door().magic(), DOOR_MAGIC);
    wake(HostCtx::NONE, Ticket::NONE);
}
