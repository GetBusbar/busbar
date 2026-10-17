// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/rows.rs`: the registry, read through the contract's view.

use std::sync::Arc;

use busbar_contract::plugin_rows::{NeedLevel, PluginRows, Trust};
use busbar_contract::store_calls::StoreDoor;

use crate::{LinkedPlugin, PluginRegistry};

/// A registry holding the build's store fixture as its linked in-process store.
fn registry() -> PluginRegistry {
    let door = crate::both_ways::store_fixture::door;
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::store("the-store", door, true)])
        .expect("the linked row registers")
}

/// A linked row reads back as the manifest it states: its name, kind, version, the trust a linked
/// row has, and the store's own statements. RED by reading the row off the wrong field: a row that
/// read `linked` off the trust verdict (a linked row is not first-party SIGNED) would answer false.
#[test]
fn a_linked_store_row_reads_back_through_the_view() {
    let rows: &dyn PluginRows = &registry();
    let row = rows.resolve("the-store").expect("the row resolves by name");
    assert_eq!(
        (row.name.as_str(), row.alias.as_str()),
        ("the-store", "the-store")
    );
    assert_eq!(row.kind, busbar_contract::abi::mechanism::kind::STORE);
    assert_eq!(row.abi_version, busbar_contract::abi::store::ABI_VERSION);
    assert_eq!(row.file, crate::registry::LINKED_FILE);
    assert!(row.linked && row.in_process && row.ephemeral);
    assert!(matches!(row.trust, Trust::Trusted { .. }));
    assert_eq!(
        (row.needs_prompt, row.needs_user),
        (NeedLevel::No, NeedLevel::No)
    );
    assert_eq!(rows.linked(), vec![row]);
    assert!(rows.loadable().is_empty() && rows.skipped().is_empty());
}

/// The store door and the refusals answer as the registry's own.
#[test]
fn the_store_door_and_the_refusals_are_the_registrys() {
    let reg = registry();
    let rows: &dyn PluginRows = &reg;
    assert!(matches!(
        rows.store_door("the-store"),
        Ok(StoreDoor::Linked(_))
    ));
    assert_eq!(
        rows.store_door("nope").map(|_| ()).unwrap_err(),
        reg.store_door("nope").map(|_| ()).unwrap_err()
    );
    assert!(rows.resolve("nope").is_none() && rows.unresolved_reason("nope").is_none());
    assert_eq!(rows.secret_refusal("nope"), reg.secret_refusal("nope"));
}

/// The root gets its own registry back through the view, by reference and owned; RED: a view
/// that is not a registry is no registry.
#[test]
fn the_root_gets_its_registry_back() {
    let rows: Arc<dyn PluginRows> = Arc::new(registry());
    let reg = crate::rows::registry_of(rows.as_ref()).expect("the view is a registry");
    assert!(reg.resolve("the-store").is_some());
    let owned = crate::rows::registry_arc(rows).expect("owned, too");
    assert!(owned.resolve("the-store").is_some());

    struct NotARegistry;
    impl PluginRows for NotARegistry {
        fn resolve(&self, _: &str) -> Option<busbar_contract::plugin_rows::Row> {
            None
        }
        fn unresolved_reason(&self, _: &str) -> Option<busbar_contract::plugin_rows::Skipped> {
            None
        }
        fn loadable(&self) -> Vec<busbar_contract::plugin_rows::Row> {
            Vec::new()
        }
        fn linked(&self) -> Vec<busbar_contract::plugin_rows::Row> {
            Vec::new()
        }
        fn skipped(&self) -> Vec<busbar_contract::plugin_rows::Skipped> {
            Vec::new()
        }
        fn store_door(&self, _: &str) -> Result<StoreDoor, String> {
            Err(String::new())
        }
        fn secret_refusal(&self, _: &str) -> String {
            String::new()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn into_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
            self
        }
    }
    assert!(crate::rows::registry_of(&NotARegistry).is_none());
}
