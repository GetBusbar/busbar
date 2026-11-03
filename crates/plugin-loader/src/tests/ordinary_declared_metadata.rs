// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable declaration metadata through the actual SQLite operation table.
use crate::actual_store;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::sdk::door::abi_str;
use std::sync::{Arc, OnceLock};

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

type ObservedOpen = (Vec<u8>, Vec<Vec<u8>>);
static OPENED: std::sync::Mutex<Option<ObservedOpen>> = std::sync::Mutex::new(None);
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
    let secrets = if written.secrets_len == 0 {
        Vec::new()
    } else {
        // SAFETY: OPEN's host-owned secret blob array lives through this crossing.
        unsafe { std::slice::from_raw_parts(written.secrets, written.secrets_len) }
            .iter()
            .map(|blob| {
                if blob.len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: each initialized secret blob is lent through this OPEN call.
                    unsafe { std::slice::from_raw_parts(blob.ptr, blob.len) }.to_vec()
                }
            })
            .collect()
    };
    *OPENED.lock().unwrap() = Some((bytes, secrets));
    let actual = actual_store::door();
    // SAFETY: the actual Store's operation table is validated and permanently retained.
    let ops = unsafe { &*actual.ops().cast::<busbar_contract::abi::store::Ops>() };
    // SAFETY: delegate the unchanged OPEN instance and live host input/output frames to
    // the retained Store operation; observation above neither mutates nor retains them.
    unsafe { ops.head.open.expect("actual SQLite OPEN")(instance, input, out) }
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
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_linked::<Store>(
        &LinkedRow::of(observed_store).expect("observed actual Store descriptor"),
        Bind {
            instance: Arc::from("observed-store-open"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual Store operation table loads");
    let settings = actual_store::settings();
    let opened =
        crate::store_v3::LoadedStore::open(plugin, dispatcher, &settings, actual_store::mint)
            .expect("the production Store host opens its actual SQLite database");
    // SQLite declares one license_key slot. An absent key still has an empty ABI
    // placeholder; no secret value is lent, and the settings stay byte-identical.
    assert_eq!(*OPENED.lock().unwrap(), Some((settings, vec![Vec::new()])));
    drop(opened);
}

extern "C" fn referencing() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    const REFS: &[AbiStr] = &[abi_str("password")];
    let address = *SLOT.get_or_init(|| {
        use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS};
        use busbar_contract::abi::mechanism::extensions::{encode, EXT_REFERENCE_FIELDS};
        let actual = *actual_store::door();
        // SAFETY: actual Store descriptor was validated and remains retained.
        let mut statement = unsafe { *actual.statement() };
        let original = if statement.extensions.len == 0 {
            Vec::new()
        } else {
            // SAFETY: this valid immutable extension range belongs to the retained product.
            unsafe {
                std::slice::from_raw_parts(statement.extensions.ptr, statement.extensions.len)
            }
            .to_vec()
        };
        // Replace the product's existing reference_fields entry rather than appending
        // a duplicate: extension lookup deliberately reads the first entry.
        let mut entries: Vec<_> = busbar_contract::abi::mechanism::extensions::entries(&original)
            .filter(|(key, _)| *key != EXT_REFERENCE_FIELDS.as_bytes())
            .map(|(key, value)| {
                (
                    std::str::from_utf8(key).expect("extension key UTF-8"),
                    value,
                )
            })
            .collect();
        entries.push((EXT_REFERENCE_FIELDS, br#"["url"]"#));
        let extensions = encode(&entries);
        let extensions = Box::leak(extensions.into_boxed_slice());
        statement.extensions = Blob {
            ptr: extensions.as_ptr(),
            len: extensions.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        statement.secret_refs = REFS.as_ptr();
        statement.secret_refs_len = REFS.len();
        let statement = Box::leak(Box::new(statement));
        // SAFETY: genuine operations unchanged, only valid retained declaration metadata restated.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                statement,
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: immutable metadata descriptor is permanently retained.
    unsafe { &*(address as *const Door) }
}
#[test]
fn reference_capable_and_secret_fields_are_independently_read_from_the_actual_descriptor() {
    let plugin = load(referencing);
    assert_eq!(plugin.reference_fields(), ["url".to_string()]);
    assert_eq!(plugin.secret_refs(), ["password".to_string()]);
}
