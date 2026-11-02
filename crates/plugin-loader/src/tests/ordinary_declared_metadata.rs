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
