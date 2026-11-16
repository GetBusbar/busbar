// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pin current ABI generations, including semantic changes without layout changes.

use std::os::raw::c_void;

use busbar_contract::abi::mechanism::call::{Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::{auth, export, hook, plane, secret, store, transport};

// The versions v1.5.5 shipped (tag v1.5.5). These never change: 1.6.0 is each one plus one.
/// `plugin-abi/src/lib.rs:71` `TRANSPORT_VERSION`.
const V155_MECHANISM: u32 = 1;
/// `plugin-abi/src/lib.rs:128`.
const V155_STORE: u32 = 2;
/// `plugin-abi/src/lib.rs:379`.
const V155_SECRET: u32 = 1;
/// `plugin-abi/src/lib.rs:395`.
const V155_AUTH: u32 = 2;
/// `plugin-abi/src/hook.rs:38`.
const V155_HOOK: u32 = 1;
/// `plugin-abi/src/export.rs:36`.
const V155_EXPORT: u32 = 2;

#[test]
fn every_abi_version_is_its_v155_value_plus_one() {
    assert_eq!(busbar_contract::abi::ABI_MAJOR, 1);
    assert_eq!(busbar_contract::abi::ABI_MINOR, 0);
    assert_eq!(MECHANISM_VERSION, V155_MECHANISM + 1);
    assert_eq!(store::ABI_VERSION, V155_STORE + 1);
    assert_eq!(secret::ABI_VERSION, V155_SECRET + 1);
    assert_eq!(auth::ABI_VERSION, V155_AUTH + 1);
    assert_eq!(hook::ABI_VERSION, V155_HOOK + 1);
    assert_eq!(export::ABI_VERSION, V155_EXPORT + 1);
    // Plane and Transport are new kinds since v1.5.5: they start at 1.
    assert_eq!(plane::ABI_VERSION, 1);
    assert_eq!(transport::ABI_VERSION, 1);
    assert_eq!(store::v4::ABI_VERSION, store::ABI_VERSION);
    // The public Store kind exposes the current primitive table directly.
    assert_eq!(store::v4::LAYOUT_FINGERPRINT, store::LAYOUT_FINGERPRINT);
    assert_eq!(store::LAYOUT_FINGERPRINT, 0xb74ff4246792db2d);
}

/// One home per number: every public version constant is the one `versions.rs` states.
#[test]
fn every_version_constant_is_read_from_versions_rs() {
    use busbar_contract::abi::versions::{self, AbiVersion};
    for (constant, home) in [
        (MECHANISM_VERSION, versions::MECHANISM),
        (store::ABI_VERSION, versions::STORE),
        (secret::ABI_VERSION, versions::SECRET),
        (auth::ABI_VERSION, versions::AUTH),
        (hook::ABI_VERSION, versions::HOOK),
        (export::ABI_VERSION, versions::EXPORT),
        (plane::ABI_VERSION, versions::PLANE),
        (transport::ABI_VERSION, versions::TRANSPORT),
    ] {
        assert_eq!(AbiVersion::from_wire(constant), home);
        assert_eq!(home.to_string(), constant.to_string());
    }
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
        type Kind = busbar_contract::plugin::markers::SecretKind;
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
    use busbar_contract::abi::{
        mechanism::call::Outcome,
        sdk::{life::Held, Instance, Lent, Out, SafeSlot},
        secret,
    };
    struct Resolve;
    impl SafeSlot for Resolve {
        type Kind = busbar_contract::plugin::markers::SecretKind;
        type In = secret::ResolveIn;
        type Out = secret::ResolveOut;
        type State = Held<Life>;
        fn call(
            _: Instance<'_, Held<Life>, Self::Kind>,
            _: Lent<'_, Self::In>,
            mut out: Out<'_, Self::Out>,
        ) -> Outcome {
            out.set(|o| &o.error_kind, secret::ERROR_KIND_NOT_FOUND);
            Outcome::Failed
        }
    }
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement("a-door", "0", 1),
        lifecycle: life(Life),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
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

#[test]
fn auth_v4_appends_serve_after_target_and_nothing_else() {
    use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
    use std::mem::{offset_of, size_of};
    assert_eq!(auth::KIND_SLOTS, 8);
    assert_eq!(auth::slot::SERVE, auth::slot::TARGET + 1);
    assert_eq!(auth::slot::SERVE, LIFECYCLE_SLOTS + 7);
    assert_eq!(
        offset_of!(auth::Ops, serve),
        8 + 8 * auth::slot::SERVE as usize
    );
    assert_eq!(size_of::<auth::Ops>(), 8 + 8 * auth::SLOTS as usize);
    // `CAP_PROVISION` is a new caps bit; the old bits keep their values.
    assert_eq!(
        (
            auth::CAP_INBOUND,
            auth::CAP_LOGIN,
            auth::CAP_OUTBOUND,
            auth::CAP_PROVISION
        ),
        (1, 2, 4, 8)
    );
}

#[test]
fn the_auth_serve_in_is_the_hook_serve_in_plus_the_verified_client() {
    use std::mem::{offset_of, size_of};
    // Byte for byte the hook shape, then one appended `client`.
    assert_eq!(
        offset_of!(auth::ServeIn, method),
        offset_of!(hook::ServeIn, method)
    );
    assert_eq!(
        offset_of!(auth::ServeIn, path),
        offset_of!(hook::ServeIn, path)
    );
    assert_eq!(
        offset_of!(auth::ServeIn, query),
        offset_of!(hook::ServeIn, query)
    );
    assert_eq!(
        offset_of!(auth::ServeIn, headers),
        offset_of!(hook::ServeIn, headers)
    );
    assert_eq!(
        offset_of!(auth::ServeIn, body),
        offset_of!(hook::ServeIn, body)
    );
    assert_eq!(
        offset_of!(auth::ServeIn, client),
        size_of::<hook::ServeIn>()
    );
    assert_eq!(size_of::<auth::ServeOut>(), size_of::<hook::ServeOut>());
}
