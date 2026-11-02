// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Qualified SQLite Store image and isolated databases for ordinary ABI controls.
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::store::OpId;
use std::sync::{Arc, OnceLock};

pub(crate) fn path() -> std::path::PathBuf {
    let path = std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
        .map(std::path::PathBuf::from)
        .expect("BUSBAR_TEST_SQLITE_CDYLIB names the qualified real SQLite product");
    assert!(
        path.is_absolute() && path.is_file(),
        "actual SQLite image: {}",
        path.display()
    );
    path
}

pub(crate) extern "C" fn door() -> &'static Door {
    static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let lib = crate::dlopen_on_worker(path().as_os_str()).expect("load actual SQLite image");
        // SAFETY: the qualified product exports the typed ABI entry; IMAGE retains its mapping.
        let entry = unsafe {
            *lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                .expect("SQLite door export")
        };
        (lib, entry)
    });
    let raw = crate::dispatch::load::enter_door(image.1);
    crate::dispatch::load::validate_door::<Store>(raw)
        .expect("actual SQLite Store descriptor validates");
    // SAFETY: descriptor validation established a live immutable door in retained IMAGE.
    let door = unsafe { &*raw };
    // SAFETY: validated descriptor names a live immutable Statement retained by IMAGE.
    let rendered =
        unsafe { busbar_contract::abi::mechanism::rendering::render(&*door.statement()) }
            .expect("SQLite statement renders");
    let stated = busbar_contract::abi::mechanism::rendering::read(&rendered)
        .expect("SQLite statement reads");
    assert_eq!(
        stated.name, "busbar-store-sqlite",
        "require actual SQLite product"
    );
    door
}

pub(crate) fn mint() -> OpId {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        std::process::id() as u64,
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

pub(crate) fn settings() -> Vec<u8> {
    // Each sibling includes this ordinary helper independently. Reserve the directory
    // atomically, so their local counters cannot accidentally share a database.
    let dir = loop {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let candidate = std::env::temp_dir().join(format!(
            "busbar-loader-real-sqlite-{}-{nanos}-{}",
            std::process::id(),
            mint().counter()
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("reserve actual SQLite database directory: {error}"),
        }
    };
    serde_json::to_vec(&serde_json::json!({"db_path": dir.join("store.sqlite3")}))
        .expect("SQLite settings")
}

pub(crate) fn open() -> LoadedStore {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(door).expect("actual SQLite row");
    let plugin = load_linked::<Store>(
        &row,
        Bind {
            instance: "actual-sqlite-abi".into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual SQLite Store links");
    LoadedStore::open(plugin, dispatcher, &settings(), mint)
        .expect("isolated actual SQLite database opens")
}
