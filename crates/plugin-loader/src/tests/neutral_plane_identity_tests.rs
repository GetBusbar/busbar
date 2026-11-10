// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::dispatch::{
    rendering_of, rendering_of_loaded, rendering_of_macro, LinkedRow, LoadedDoor,
};

#[path = "neutral_kind_rename_tests.rs"]
mod neutral_kind_rename_tests;

#[test]
fn neutral_plane_function_macro_and_loaded_rows_preserve_the_same_door_and_statement() {
    let door = crate::neutral_plane::door;
    let macro_door = crate::neutral_plane::MACRO_DOOR;
    let restated = unsafe { LoadedDoor::from_raw(crate::dispatch::load::raw(door)) };
    assert_eq!(door as *const () as usize, macro_door.door_fn() as usize);
    let by_fn = LinkedRow::of(door).expect("actual function door states itself");
    let by_macro = LinkedRow::of_macro(macro_door).expect("actual macro handle states itself");
    let by_loaded = LinkedRow::of_loaded(restated).expect("actual loaded door states itself");
    assert_eq!(by_fn.statement, by_macro.statement);
    assert_eq!(by_fn.statement, by_loaded.statement);
    assert_eq!(by_fn.door as usize, by_macro.door as usize);
    assert_eq!(by_fn.door as usize, by_loaded.door as usize);
    assert_eq!(
        rendering_of(door).unwrap(),
        rendering_of_macro(macro_door).unwrap()
    );
    assert_eq!(
        rendering_of(door).unwrap(),
        rendering_of_loaded(restated).unwrap()
    );

    use crate::dispatch::kinds::plane::Plane;
    use crate::dispatch::{load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink};
    use std::sync::Arc;
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let bind = |row: &LinkedRow| {
        load_linked::<Plane>(
            row,
            Bind {
                instance: "neutral-plane-identity".into(),
                max_inflight_cap: 8,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Probe,
            },
        )
        .expect("the actual plane descriptor binds")
    };
    let linked = bind(&by_fn);
    let linked_macro = bind(&by_macro);
    let linked_loaded = bind(&by_loaded);
    let shape = |plugin: &crate::dispatch::Plugin<Plane>| {
        (
            plugin.name().to_string(),
            plugin.kind(),
            plugin.max_inflight(),
        )
    };
    assert_eq!(shape(&linked), shape(&linked_macro));
    assert_eq!(shape(&linked), shape(&linked_loaded));
}

#[test]
fn neutral_dropped_plane_bytes_enter_the_production_staging_path_once() {
    use crate::dispatch::{
        load_dropped_bytes, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };
    use std::sync::Arc;
    let bytes =
        std::fs::read(crate::neutral_plane::cdylib()).expect("read the neutral SDK plane image");
    let stated = rendering_of(crate::neutral_plane::door).expect("neutral SDK plane statement");
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let before = crate::stage::STAGED_HERE.with(std::cell::Cell::get);
    let plugin = load_dropped_bytes::<crate::dispatch::kinds::plane::Plane>(
        &bytes,
        "neutral-plane-staged",
        &stated,
        Bind {
            instance: Arc::from("neutral-plane-staged"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .expect("neutral SDK plane bytes load through production staging");
    let staged = crate::stage::STAGED_HERE.with(std::cell::Cell::get) - before;
    assert_eq!(
        staged, 1,
        "the actual dropped image must stage once rather than load its build path"
    );
    drop(plugin);
}
