// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The opaque transport-configuration handle (#40(b), #36): a transport can USE the
//! configuration the kernel built, as the type it was built as, and cannot read it any other way.
//!
//! The configuration type below is made up on purpose. The contract names no session-layer crate, so
//! the handle has to work for a type it has never heard of; a fixture that borrowed a real one would
//! be unable to tell "the handle is generic" from "the handle happens to fit the one type it was
//! written beside".

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{Grant, KernelSeal, KeyHandle};
use busbar_contract::transport::{ConfigRole, TransportConfigHandle, TransportConfigSink};

/// A stand-in for a built session-layer configuration, holding a value that must never be printed.
#[derive(Debug, PartialEq)]
struct BuiltConfig {
    material: &'static str,
}

/// A second, unrelated type, to prove a handle does not answer as whatever the caller asks for.
struct OtherConfig;

fn grant() -> Grant<KeyHandle> {
    Grant::mint(&KernelSeal::acquire_for_kernel())
}

#[test]
fn the_configuration_comes_back_as_the_type_it_was_built_as_and_as_nothing_else() {
    let built = Arc::new(BuiltConfig {
        material: "never-printed-material",
    });
    let handle = TransportConfigHandle::issue(&grant(), 7, ConfigRole::Listen, Arc::clone(&built));

    assert_eq!(handle.slot(), 7);
    assert_eq!(handle.role(), ConfigRole::Listen);
    let used = handle
        .config::<BuiltConfig>()
        .expect("the handle yields the configuration as the type the kernel built");
    assert!(
        Arc::ptr_eq(&used, &built),
        "the handle shares the one built value; it never copies it"
    );
    assert!(
        handle.config::<OtherConfig>().is_none(),
        "a handle must not answer as a type it was not built as"
    );
}

#[test]
fn debug_prints_the_slot_and_role_and_never_the_configuration() {
    let handle = TransportConfigHandle::issue(
        &grant(),
        3,
        ConfigRole::Dial,
        Arc::new(BuiltConfig {
            material: "never-printed-material",
        }),
    );
    let dbg = format!("{handle:?}");
    assert!(!dbg.contains("never-printed-material"), "{dbg}");
    assert!(!dbg.contains("BuiltConfig"), "{dbg}");
    assert!(dbg.contains("slot: 3"), "{dbg}");
    assert!(dbg.contains("Dial"), "{dbg}");
}

#[test]
fn a_sink_receives_the_handle_the_kernel_side_issued() {
    #[derive(Default)]
    struct Sink(Mutex<Vec<TransportConfigHandle>>);
    impl TransportConfigSink for Sink {
        fn register_config(&self, handle: TransportConfigHandle) {
            self.0.lock().expect("unpoisoned").push(handle);
        }
    }

    let sink = Sink::default();
    let registered: &dyn TransportConfigSink = &sink;
    registered.register_config(TransportConfigHandle::issue(
        &grant(),
        11,
        ConfigRole::Dial,
        Arc::new(BuiltConfig { material: "m" }),
    ));

    let got = sink.0.lock().expect("unpoisoned");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].slot(), 11);
    assert_eq!(got[0].role(), ConfigRole::Dial);
    assert_eq!(
        got[0].config::<BuiltConfig>().as_deref(),
        Some(&BuiltConfig { material: "m" })
    );
}
