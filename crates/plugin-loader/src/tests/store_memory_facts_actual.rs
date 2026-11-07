// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The former store fixture's descriptor facts checked on the actual memory product.
use crate::dispatch::kinds::store_v4::StoreV4 as Store;
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::sdk::door::RawDoorFn;
use std::sync::OnceLock;
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

#[tokio::test]
async fn actual_memory_open_reports_ephemeral_native_metadata() {
    use crate::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use crate::store_v4::{Limits, LoadedPersistence};
    use busbar_contract::persistence::{Durability, PersistenceBackend};
    use std::sync::Arc;
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
    let opened = LoadedPersistence::open(
        plugin,
        dispatcher,
        b"{}",
        Limits {
            descriptor_bytes: 4096,
            output_items: 4096,
            output_bytes: 64 * 1024,
            decode_bytes: 128 * 1024,
        },
    )
    .await
    .expect("actual memory Store opens");
    let info = opened.info();
    assert_eq!(info.durability, Durability::Ephemeral);
    let observed = opened.clock(info.dataset).await.expect("native clock");
    assert_eq!(observed.authority, info.clock_authority);
}
