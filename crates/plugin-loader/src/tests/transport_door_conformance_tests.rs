// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{
    load_dropped, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, LoadError,
    NoSink,
};

#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let path = crate::neutral_transport::cdylib();
    let row = LinkedRow::of(crate::neutral_transport::door).expect("the SDK witness states itself");
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
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
        other => panic!(
            "the linked witness door loaded as a hook: {:?}",
            other.err()
        ),
    }
    match load_dropped::<Hook>(&path, &row.statement, bind()) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => {
            assert_eq!((stated, asked), want);
        }
        other => panic!(
            "the dropped-in witness door loaded as a hook: {:?}",
            other.err()
        ),
    }
}
