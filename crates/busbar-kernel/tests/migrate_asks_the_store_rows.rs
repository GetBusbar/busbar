// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MIGRATOR ASKS THE STORE ROWS (owner ruling Q4, 2026-10-03: core names no plugin; it asks each
//! plugin what it is). A 1.4.x `governance:` block that names a store module and a `db_path` is
//! migrated by what the named store's linked row STATES, never by its name: a row that states what it
//! holds is lost on restart keeps no file, so the path is dropped; any other row takes it.
//!
//! Its own test binary: the composition root's rows install once per process (first install
//! stands), so the rows below must be the first thing this process installs.

use busbar_kernel::config::migrate::migrate_config;
use busbar_kernel::governance::RecordStore;
use busbar_kernel::preflight::{install_linked_rows, LinkedStore, RootInstall};

fn never(_: &str) -> Result<Box<dyn RecordStore>, String> {
    Err(String::new())
}

extern "C" fn no_door() -> *const busbar_contract::abi::mechanism::door::Door {
    std::ptr::null()
}

/// Two store rows the kernel has never heard of: one volatile (and the default), one durable.
const STORES: &[LinkedStore] = &[
    ("acme-volatile", true, true, never, no_door),
    ("acme-durable", false, false, never, no_door),
];

fn install() {
    install_linked_rows(RootInstall {
        stores: STORES,
        default_store_module: "acme-volatile",
        ..RootInstall::default()
    });
}

fn migrated_store(module: &str) -> serde_yaml::Value {
    let raw = format!("governance:\n  store: {module}\n  db_path: /var/lib/acme/ledger.db\n");
    let out = migrate_config(&raw).expect("the 1.4.x block migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("the output parses");
    doc["store"].clone()
}

#[test]
fn a_volatile_store_row_keeps_no_db_path_and_a_durable_one_takes_it() {
    install();

    let volatile = migrated_store("acme-volatile");
    assert_eq!(volatile["module"].as_str(), Some("acme-volatile"));
    assert!(
        volatile.get("settings").is_none(),
        "a store row that states it is ephemeral has nowhere to put a db_path: {volatile:?}"
    );

    let durable = migrated_store("acme-durable");
    assert_eq!(durable["module"].as_str(), Some("acme-durable"));
    assert_eq!(
        durable["settings"]["url"].as_str(),
        Some("/var/lib/acme/ledger.db"),
        "a durable store row takes the path: {durable:?}"
    );
}
