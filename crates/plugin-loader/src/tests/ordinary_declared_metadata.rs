// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable declaration metadata through the actual SQLite operation table.
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::sdk::door::abi_str;
use std::sync::{Arc, OnceLock};
#[path = "actual_store.rs"]
mod actual_store;

fn restated(slot: &OnceLock<usize>, refs: &'static [AbiStr]) -> &'static Door {
    let addr = *slot.get_or_init(|| {
        let actual = *actual_store::door();
        // SAFETY: the qualified image is retained; its immutable descriptor was validated.
        let mut statement = unsafe { *actual.statement() };
        statement.secret_refs = refs.as_ptr();
        statement.secret_refs_len = refs.len();
        let statement = Box::leak(Box::new(statement));
        // SAFETY: all operations remain the actual product's. Only the immutable metadata
        // under examination is replaced by permanently retained valid ABI strings.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                statement,
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: this immutable descriptor was leaked above and remains live.
    unsafe { &*(addr as *const Door) }
}
extern "C" fn declaring() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    const REFS: &[AbiStr] = &[abi_str("dsn"), abi_str("replicas.*.password")];
    restated(&SLOT, REFS)
}
extern "C" fn silent() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    restated(&SLOT, &[])
}
fn load(door: busbar_contract::abi::mechanism::door::DoorFn) -> crate::dispatch::Plugin<Store> {
    let d = Dispatcher::new(DispatchConfig::default());
    load_linked::<Store>(
        &LinkedRow::of(door).expect("actual descriptor states itself"),
        Bind {
            instance: Arc::from("declared-metadata"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual operation table loads with its declared metadata")
}
#[test]
fn a_store_door_states_its_declared_secret_paths() {
    assert_eq!(
        load(declaring).secret_refs(),
        ["dsn".to_string(), "replicas.*.password".to_string()]
    );
    assert!(load(silent).secret_refs().is_empty());
}

static OPENED: std::sync::Mutex<Option<(Vec<u8>, usize)>> = std::sync::Mutex::new(None);
extern "C" fn observe_open(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    // SAFETY: OPEN receives the host's initialized frame; bytes stay live through delegation.
    let written = unsafe { &*input.cast::<busbar_contract::abi::mechanism::lifecycle::OpenIn>() };
    let bytes = if written.settings.len == 0 {
        Vec::new()
    } else {
        // SAFETY: these settings are supplied by this test's live host-owned allocation.
        unsafe { std::slice::from_raw_parts(written.settings.ptr, written.settings.len) }.to_vec()
    };
    *OPENED.lock().unwrap() = Some((bytes, written.secrets_len));
    let actual = actual_store::door();
    // SAFETY: the actual Store's operation table is validated and permanently retained.
    let ops = unsafe { &*actual.ops().cast::<busbar_contract::abi::store::Ops>() };
    ops.head.open.expect("actual SQLite OPEN")(instance, input, out)
}
extern "C" fn observed_store() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    let ptr = *SLOT.get_or_init(|| {
        let actual = *actual_store::door();
        // SAFETY: qualified Store metadata and table are validated and retained.
        let mut ops = unsafe {
            actual
                .ops()
                .cast::<busbar_contract::abi::store::Ops>()
                .read_unaligned()
        };
        ops.head.open = Some(observe_open);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: only a passive forwarding OPEN observer changes; genuine SQLite owns all behavior.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: immutable descriptor remains live permanently.
    unsafe { &*(ptr as *const Door) }
}
#[test]
fn the_store_host_lends_nothing_and_hands_the_settings_as_resolved() {
    use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_JSON};
    let plugin = load(observed_store);
    let settings = actual_store::settings();
    let mut frame = crate::dispatch::lifecycle::open_frame(Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    });
    assert_eq!(
        plugin
            .call(
                busbar_contract::abi::mechanism::lifecycle::slot::OPEN,
                &mut frame
            )
            .outcome,
        Outcome::Ready
    );
    assert_eq!(*OPENED.lock().unwrap(), Some((settings, 0)));
    crate::dispatch::lifecycle::close(&plugin);
}
