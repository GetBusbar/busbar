// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The first-party anti-downgrade floor the store keeps per host, across a restart.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::plugin_rows::{NeedLevel, PluginRows, Row, Skipped, Trust};

use super::hold;

/// The rows a scan admitted: dropped-in first-party plugins at the versions named.
#[derive(Debug)]
struct Scanned(Vec<Row>);

fn first_party(name: &str, version: &str) -> Row {
    Row {
        file: format!("{name}-{version}.tar.gz"),
        key: name.to_string(),
        name: name.to_string(),
        alias: name.to_string(),
        kind: "hook".to_string(),
        version: version.to_string(),
        abi_version: 1,
        trust: Trust::Trusted {
            publisher: "busbar".to_string(),
            first_party: true,
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    }
}

impl PluginRows for Scanned {
    fn resolve(&self, name_or_alias: &str) -> Option<Row> {
        self.0.iter().find(|r| r.name == name_or_alias).cloned()
    }
    fn unresolved_reason(&self, _: &str) -> Option<Skipped> {
        None
    }
    fn loadable(&self) -> Vec<Row> {
        self.0.clone()
    }
    fn linked(&self) -> Vec<Row> {
        Vec::new()
    }
    fn skipped(&self) -> Vec<Skipped> {
        Vec::new()
    }
    fn store_door(&self, name: &str) -> Result<busbar_contract::store_calls::StoreDoor, String> {
        Err(format!("no store `{name}`"))
    }
    fn secret_refusal(&self, name: &str) -> String {
        format!("no secret `{name}`")
    }
    fn kind_refusal(&self, kind: &str, _: &str, name: &str) -> String {
        format!("no {kind} `{name}`")
    }
    fn secret_slots(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// **AN OLD SIGNED RELEASE DROPPED IN AFTER A RESTART IS REFUSED.** A host loads a first-party
/// plugin at 1.2.0; after a restart (a fresh process, the same store) the same name at 1.1.0 is
/// refused, naming the floor and the pin that rolls it back on purpose. The pin admits it, and
/// another host on the same store keeps its own floor.
///
/// RED while the floor lived in memory without a data directory: the restart forgot 1.2.0 and the
/// old release loaded with no warning.
#[test]
fn an_old_first_party_release_is_refused_after_a_restart_on_the_same_store() {
    let store = crate::root::store_double::RecordSlots::new();
    let none = BTreeMap::new();
    hold(
        store.calls().as_ref(),
        "node-a",
        &Scanned(vec![first_party("busbar-hook-x", "1.2.0")]),
        &none,
    )
    .expect("a first load sets the floor");

    // The restart: a fresh process over the same store, the older release dropped in.
    let older = Scanned(vec![first_party("busbar-hook-x", "1.1.0")]);
    let refused = hold(store.calls().as_ref(), "node-a", &older, &none)
        .expect_err("an old release does not load in the newer one's place");
    assert!(
        refused.contains("below 1.2.0") && refused.contains("first_party_floors.busbar-hook-x"),
        "the refusal names the floor and the pin: {refused}"
    );

    let pinned: BTreeMap<String, String> =
        [("busbar-hook-x".to_string(), "1.1.0".to_string())].into();
    hold(store.calls().as_ref(), "node-a", &older, &pinned).expect("the pin rolls it back");
    hold(store.calls().as_ref(), "node-b", &older, &none)
        .expect("another host keeps its own floor");
    hold(
        store.calls().as_ref(),
        "node-a",
        &Scanned(vec![first_party("busbar-hook-x", "1.3.0")]),
        &none,
    )
    .expect("a newer release loads and raises the floor");
}
