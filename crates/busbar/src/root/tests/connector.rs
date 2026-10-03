// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CONNECTOR: built from this build's linked transport doors, installed once, and the same
//! instance whoever asks for it; a second install is refused. Every path that dials or declares
//! takes this instance (`root::connector::the()`), never a connector of its own.

use super::*;

/// The strict default guard, as a deployment that states nothing builds it.
fn judge() -> Arc<dyn busbar_kernel::host_services::DestJudge> {
    process::dest_judge(&Destinations::default()).expect("the default")
}

#[test]
fn the_process_has_one_connector_and_every_path_takes_it() {
    let doors = crate::LINKED_TRANSPORT_DOORS;
    assert!(!doors.is_empty(), "this build links a transport door");
    let built = process::build(|| entries(doors), judge(), &[], Arc::new(|_| {}));
    let built = built.expect("the linked doors build a connector");
    let installed = install(Arc::clone(&built)).expect("the first install is the one");
    assert!(Arc::ptr_eq(installed, &built));
    assert!(Arc::ptr_eq(the(), &built), "the() is the installed one");
    let second = process::build(|| entries(doors), judge(), &[], Arc::new(|_| {}))
        .expect("a second one builds");
    assert!(install(second).is_err(), "a second connector is refused");
    assert!(Arc::ptr_eq(the(), &built));
}

/// A bad `advanced.allow_destinations` entry refuses the guard's build (the boot and `--validate`
/// refusal), naming the key and the entry.
#[test]
fn a_bad_allowlist_entry_refuses_the_guard() {
    let d = Destinations {
        allow: vec!["host.test:8080".into()],
        ..Destinations::default()
    };
    let refusal = process::dest_judge(&d).err().expect("refused");
    assert!(
        refusal.starts_with("advanced.allow_destinations[0]: `host.test:8080`"),
        "{refusal}"
    );
}
