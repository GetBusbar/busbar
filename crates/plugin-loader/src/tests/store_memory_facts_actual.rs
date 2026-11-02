// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The former store fixture's descriptor facts checked on the actual memory product.
use crate::dispatch::kinds::store::{Store, StoreFacts};
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::sdk::door::RawDoorFn;
use std::sync::{Arc, OnceLock};
fn path() -> std::path::PathBuf {
    let p = std::env::var_os("BUSBAR_TEST_MEMORY_STORE_CDYLIB")
        .map(std::path::PathBuf::from)
        .expect("BUSBAR_TEST_MEMORY_STORE_CDYLIB names the qualified actual memory Store");
    assert!(p.is_absolute() && p.is_file());
    p
}
pub(crate) extern "C" fn door() -> &'static Door {
    static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let lib = crate::dlopen_on_worker(path().as_os_str()).expect("load actual memory image");
        // SAFETY: the qualified product exports the typed ABI entry; IMAGE retains its mapping.
        let entry = unsafe {
            *lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                .expect("memory door export")
        };
        (lib, entry)
    });
    let raw = crate::dispatch::load::enter_door(image.1);
    crate::dispatch::load::validate_door::<Store>(raw)
        .expect("actual memory Store descriptor validates");
    // SAFETY: descriptor validation established a live immutable door in retained IMAGE.
    let door = unsafe { &*raw };
    // SAFETY: validated descriptor names a live immutable Statement retained by IMAGE.
    let rendered =
        unsafe { busbar_contract::abi::mechanism::rendering::render(&*door.statement()) }
            .expect("memory statement renders");
    let stated = busbar_contract::abi::mechanism::rendering::read(&rendered)
        .expect("memory statement reads");
    assert_eq!(stated.name, "memory", "require actual memory product");
    door
}

fn open() -> LoadedStore {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_linked::<Store>(
        &LinkedRow::of(door).expect("actual memory descriptor"),
        Bind {
            instance: "memory-facts".into(),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual memory Store links");
    LoadedStore::open(plugin, dispatcher, b"{}", crate::actual_store::mint)
        .expect("actual memory Store opens")
}
#[test]
fn the_memory_store_states_its_facts_in_its_tail() {
    let s = open();
    assert_eq!(
        s.facts(),
        StoreFacts {
            ephemeral: true,
            durable_plane: false,
            fork_refusal: true,
            record_transaction: true,
            usage_correction: true,
            secret_refs: vec!["token".into()],
            credential_rewrap: true,
        }
    );
    assert!(!s.name().is_empty(), "the store states its name");
    // Independently retain the old absence-metadata policy without inventing a Store:
    // context() is the production DATA projection over a valid immutable Statement.
    // SAFETY: the real product's validated Statement and all retained pointers are live.
    let mut absent = unsafe { *door().statement() };
    absent.extensions = busbar_contract::abi::mechanism::call::Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    };
    absent.secret_refs = std::ptr::null();
    absent.secret_refs_len = 0;
    let context = <Store as crate::dispatch::Kind>::context(&absent)
        .expect("absence metadata parses")
        .expect("Store facts context");
    assert_eq!(
        context.downcast_ref::<StoreFacts>().expect("Store facts"),
        &StoreFacts {
            ephemeral: true,
            durable_plane: false,
            fork_refusal: true,
            record_transaction: false,
            usage_correction: false,
            secret_refs: Vec::new(),
            credential_rewrap: false,
        }
    );
}

#[test]
fn the_ephemeral_store_states_mark_ephemeral_on_its_statement_not_its_tail() {
    use busbar_contract::abi::mechanism::door::MARK_EPHEMERAL;
    use busbar_contract::abi::mechanism::rendering::read;
    use busbar_contract::abi::store::StoreTail;

    let row = LinkedRow::of(door).expect("the memory store states its Statement");
    let st = read(&row.statement).expect("the rendering reads back");
    assert_eq!(st.marks & MARK_EPHEMERAL, MARK_EPHEMERAL);
    assert_eq!(st.kind_tail_size as usize, std::mem::size_of::<StoreTail>());
}
