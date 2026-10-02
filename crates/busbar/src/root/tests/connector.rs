// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CONNECTOR: built from this build's linked transport doors, installed once, and the same
//! instance whoever asks for it; a second install is refused. The egress path takes its connection
//! table from this instance (`root::plane_egress::conns`), never from a connector of its own.

use super::*;

#[test]
fn the_process_has_one_connector_and_every_path_takes_it() {
    let doors = crate::LINKED_TRANSPORT_DOORS;
    assert!(!doors.is_empty(), "this build links a transport door");
    let built = process::build(|| entries(doors), &[], &[], false, &[], Arc::new(|_| {}));
    let built = built.expect("the linked doors build a connector");
    let installed = install(Arc::clone(&built)).expect("the first install is the one");
    assert!(Arc::ptr_eq(installed, &built));
    assert!(Arc::ptr_eq(the(), &built), "the() is the installed one");
    let egress = crate::root::plane_egress::conns();
    let same: Arc<dyn busbar_contract::conn::PollConns> = Arc::clone(&built) as _;
    assert!(
        std::ptr::addr_eq(Arc::as_ptr(&egress), Arc::as_ptr(&same)),
        "the egress path's connection table is the one connector"
    );
    let second = process::build(|| entries(doors), &[], &[], false, &[], Arc::new(|_| {}))
        .expect("a second one builds");
    assert!(install(second).is_err(), "a second connector is refused");
    assert!(Arc::ptr_eq(the(), &built));
}
