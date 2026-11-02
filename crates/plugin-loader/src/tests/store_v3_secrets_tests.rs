// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::both_ways::store_fixture::MemoryStore;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::OpenIn;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::store::{OpId, Ops};
use std::sync::{Arc, Mutex, OnceLock};

#[path = "actual_store.rs"]
mod actual_store;
type OpenSeen = (Vec<u8>, Vec<Vec<u8>>);
static SEEN: Mutex<Vec<OpenSeen>> = Mutex::new(Vec::new());

extern "C" fn observed_open(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: this passive observer occupies the actual OPEN slot, whose live
    // settings and secret loans are copied only while the original crossing lives.
    unsafe {
        let request = &*input.cast::<OpenIn>();
        let settings =
            std::slice::from_raw_parts(request.settings.ptr, request.settings.len).to_vec();
        let secrets = if request.secrets_len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(request.secrets, request.secrets_len)
                .iter()
                .map(|secret| std::slice::from_raw_parts(secret.ptr, secret.len).to_vec())
                .collect()
        };
        SEEN.lock().unwrap().push((settings, secrets));
        let ops = &*actual_store::door().ops().cast::<Ops>();
        ops.head.open.expect("actual SQLite OPEN")(instance, input, output)
    }
}

extern "C" fn observing_door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let ptr = *DOOR.get_or_init(|| {
        let actual = *actual_store::door();
        // SAFETY: actual_store retains a validated immutable actual SQLite image.
        let mut ops = unsafe { actual.ops().cast::<Ops>().read_unaligned() };
        ops.head.open = Some(observed_open);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: every descriptor field is genuine; only OPEN is observed and
        // forwarded unchanged to the same original SDK instance and live frames.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: the descriptor and copied table are immutable permanent allocations.
    unsafe { &*(ptr as *const Door) }
}
fn mint() -> OpId {
    actual_store::mint()
}

#[test]
fn a_declared_store_secret_reaches_open_as_a_secret_never_in_its_settings() {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(
        &LinkedRow::of(observing_door).expect("the actual Store states itself"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the actual descriptor loads");
    let mut settings: serde_json::Value =
        serde_json::from_slice(&actual_store::settings()).unwrap();
    let db_path = settings["db_path"].clone();
    settings["license_key"] = "hunter2".into();
    let _store = LoadedStore::open(p, d, &serde_json::to_vec(&settings).unwrap(), mint)
        .expect("actual SQLite opens");
    let (seen, secrets) = SEEN.lock().unwrap().pop().expect("actual OPEN ran");
    let read: serde_json::Value = serde_json::from_slice(&seen).expect("JSON settings");
    assert_eq!(read["db_path"], db_path, "the actual plain settings stay");
    assert!(
        read.get("license_key").is_none(),
        "the declared secret rode plain settings: {read}"
    );
    assert_eq!(
        secrets,
        vec![b"hunter2".to_vec()],
        "the actual declared secret is lent to OPEN as its one secret"
    );
}

mod synchronous {
    use busbar_contract::abi::mechanism::call::AbiStr;
    const REFS: &[AbiStr] = &[super::abi_str("password")];
    busbar_contract::store_door!(super::MemoryStore, "synchronous", "0", 64, secret_refs: REFS);
}

#[test]
fn a_synchronous_store_receives_and_checks_its_declared_secret() {
    for (password, accepted) in [("hunter2", true), ("wrong", false)] {
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let p = load_linked::<Store>(
            &LinkedRow::of(synchronous::door).unwrap(),
            Bind {
                instance: Arc::from("synchronous-secret"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: crate::dispatch::ConnTable::NoNeeds,
            },
        )
        .unwrap();
        let settings = serde_json::json!({"test_require_secret":true, "password":password});
        let opened = LoadedStore::open(p, d, &serde_json::to_vec(&settings).unwrap(), mint);
        assert_eq!(
            opened.is_ok(),
            accepted,
            "the real synchronous door checks its lent secret"
        );
        if let Err(error) = opened {
            assert!(
                !error.to_string().contains(password),
                "refusal must not expose the credential"
            );
        }
    }
}
