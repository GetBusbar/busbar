// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY ABI VERSION IS ITS v1.5.5 VALUE + 1 (`BUSBAR-1.6.0.md` THE DESIGN, §11.2; owner ruling on §10;
//! `TRANSPORT_VERSION` becomes `MECHANISM_VERSION`). A kind whose ABI is new in 1.6.0 had no v1.5.5
//! value and ships 1.
//!
//! The v1.5.5 values below are READ OFF THE TAG, not remembered. Each is cited with the command
//! that prints it; re-run any of them to audit this file.

use std::os::raw::c_void;

use busbar_contract::abi::mechanism::call::{Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};
use busbar_contract::abi::{auth, export, hook, plane, secret, store, transport};

/// `git show v1.5.5:crates/plugin-abi/src/lib.rs` line 71: `pub const TRANSPORT_VERSION: u32 = 1;`
const V155_TRANSPORT_VERSION: u32 = 1;
/// `git show v1.5.5:crates/plugin-abi/src/lib.rs` line 128: `pub const ABI_VERSION: u32 = 2;`
/// (the store ABI).
const V155_STORE_ABI_VERSION: u32 = 2;
/// `git show v1.5.5:crates/plugin-abi/src/lib.rs` line 379: `pub const SECRET_ABI_VERSION: u32 = 1;`
const V155_SECRET_ABI_VERSION: u32 = 1;
/// `git show v1.5.5:crates/plugin-abi/src/lib.rs` line 395: `pub const AUTH_ABI_VERSION: u32 = 2;`
const V155_AUTH_ABI_VERSION: u32 = 2;
/// `git show v1.5.5:crates/plugin-abi/src/hook.rs` line 38: `pub const HOOK_ABI_VERSION: u32 = 1;`
const V155_HOOK_ABI_VERSION: u32 = 1;
/// `git show v1.5.5:crates/plugin-abi/src/export.rs` line 36: `pub const EXPORT_ABI_VERSION: u32 = 2;`
const V155_EXPORT_ABI_VERSION: u32 = 2;
/// v1.5.5 had no plane ABI: `git grep -nE 'const [A-Z_]+: u32' v1.5.5 -- 'crates/*.rs'` names the
/// six versions above and no plane version.
const V155_PLANE_ABI_VERSION: u32 = 0;
/// v1.5.5 had no transport kind ABI: the same command names none (`TRANSPORT_VERSION` was the
/// mechanism's number, above).
const V155_TRANSPORT_KIND_ABI_VERSION: u32 = 0;

#[test]
fn every_abi_version_is_its_v155_value_plus_one() {
    assert_eq!(MECHANISM_VERSION, V155_TRANSPORT_VERSION + 1);
    assert_eq!(MECHANISM_VERSION, 2);
    assert_eq!(store::ABI_VERSION, V155_STORE_ABI_VERSION + 1);
    assert_eq!(store::ABI_VERSION, 3);
    assert_eq!(secret::ABI_VERSION, V155_SECRET_ABI_VERSION + 1);
    assert_eq!(secret::ABI_VERSION, 2);
    assert_eq!(auth::ABI_VERSION, V155_AUTH_ABI_VERSION + 1);
    assert_eq!(auth::ABI_VERSION, 3);
    assert_eq!(hook::ABI_VERSION, V155_HOOK_ABI_VERSION + 1);
    assert_eq!(hook::ABI_VERSION, 2);
    assert_eq!(export::ABI_VERSION, V155_EXPORT_ABI_VERSION + 1);
    assert_eq!(export::ABI_VERSION, 3);
    assert_eq!(plane::ABI_VERSION, V155_PLANE_ABI_VERSION + 1);
    assert_eq!(plane::ABI_VERSION, 1);
    assert_eq!(transport::ABI_VERSION, V155_TRANSPORT_KIND_ABI_VERSION + 1);
    assert_eq!(transport::ABI_VERSION, 1);
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
    // The retired lane's magic can never be read as a door.
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

// THE SLOT TYPES ARE `extern "C"`. Each item below is a plain `extern "C" fn`; it coerces to the
// slot type only if the slot type is `extern "C"` too — an `extern "C-unwind"` slot type would not
// compile here.
extern "C" fn an_op(_i: *mut c_void, _in: *const c_void, _out: *mut c_void) -> RawOutcome {
    RawOutcome::of(Outcome::Ready)
}
extern "C" fn a_door() -> *const Door {
    std::ptr::null()
}
extern "C" fn a_wake(_c: HostCtx, _t: Ticket) {}

#[test]
fn every_slot_type_is_extern_c() {
    let op: Op = an_op;
    let door: DoorFn = a_door;
    let wake: WakeFn = a_wake;
    assert_eq!(
        op(std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut()).outcome(),
        Outcome::Ready
    );
    assert!(door().is_null());
    wake(
        HostCtx {
            ptr: std::ptr::null_mut(),
        },
        Ticket::NONE,
    );
}
