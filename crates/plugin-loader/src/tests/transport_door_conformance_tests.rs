// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::mechanism::{KindCode, DOOR_SYMBOL};
use busbar_contract::abi::sdk::door::RawDoorFn;

use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{
    load_dropped, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, LoadError,
    NoSink,
};

// Carrier bytes, pending exchanges, and complete linked/dropped transcript parity belong to
// the actual TCP product's conformance test, the_linked_and_the_dropped_in_door_are_one_plugin.
// Its BUSBAR_CONFORMANCE_RED=count branch also checks the transcript count comparator.
// Keep the separate loader-boundary refusal here: descriptor validation alone does not exercise
// either load_linked or load_dropped's manifest kind check.
#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let path = std::env::var_os("BUSBAR_TEST_TCP_CDYLIB")
        .map(PathBuf::from)
        .expect("BUSBAR_TEST_TCP_CDYLIB must name the qualified real TCP image");
    let image = crate::dlopen_on_worker(path.as_os_str()).expect("the real TCP image loads");
    // SAFETY: the qualified image exports the mechanism's typed door symbol. The image
    // remains live until both load attempts and their immutable Statement have been dropped.
    let door = unsafe {
        *image
            .get::<RawDoorFn>(DOOR_SYMBOL)
            .expect("the real TCP door")
    };
    let row = LinkedRow::of_raw(door).expect("the actual TCP door states itself");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = || Bind {
        instance: "transport-kind-refusal".into(),
        max_inflight_cap: 16,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::NoNeeds,
    };
    let want = (KindCode::Transport, KindCode::Hook);
    match load_linked::<Hook>(&row, bind()) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => {
            assert_eq!((stated, asked), want);
        }
        other => panic!("the linked TCP door loaded as a hook: {:?}", other.err()),
    }
    match load_dropped::<Hook>(&path, &row.statement, bind()) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => {
            assert_eq!((stated, asked), want);
        }
        other => panic!(
            "the dropped-in TCP door loaded as a hook: {:?}",
            other.err()
        ),
    }
}
