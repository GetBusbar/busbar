// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: secret`, BOTH WAYS** (DECISIONS #2 rule (1), K5). The in-tree secret example registered
//! through the LINKED door (its `rlib`'s `BUSBAR_COLD_ENTRY`) and the DROPPED-IN door (its `cdylib`,
//! signed into `plugins/`) resolves to the byte-identical registry row, and the module each door's
//! `open_secret` opens resolves one script byte-identically — a hit, a miss and a malformed
//! reference, the two refusals with their kind and text. See [`super::both_ways`].
//!
//! RED by planting the door bypass the axis replaces — linked rows handed to [`PluginRegistry::link`]
//! and never registered — which leaves the linked registry with no row for the name.

use super::both_ways::{both_doors, statement};
use busbar_api::SecretModule;

/// The script: resolve a configured key, an unconfigured one and a reference with no `key`.
fn script(module: &dyn SecretModule) -> String {
    let settings = |key: Option<&str>| {
        let mut m = serde_json::Map::new();
        if let Some(k) = key {
            m.insert("key".into(), serde_json::Value::String(k.into()));
        }
        m
    };
    [Some("db-password"), Some("no-such-key"), None]
        .into_iter()
        .map(|key| match module.resolve(&settings(key)) {
            Ok(bytes) => format!("{key:?} -> ok {}", String::from_utf8_lossy(&bytes)),
            Err(e) => format!("{key:?} -> err {e}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// THE EXIT TEST: the secret example linked and dropped in registers the same row and opens a module
/// that resolves the same.
#[test]
fn a_linked_and_a_dropped_in_secret_module_register_byte_identical_rows() {
    let manifest = statement(
        "secret",
        "secret-example",
        "example-secret",
        busbar_plugin::cold::SECRET_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        &busbar_secret_example_plugin::BUSBAR_COLD_ENTRY,
        "busbar_secret_example_plugin",
        |registry| {
            registry
                .open_secret("example-secret", r#"{"map": {"db-password": "hunter2"}}"#)
                .expect("the secret module opens through its alias")
        },
        |opened| script(opened.as_ref()),
    ) else {
        eprintln!("skip: secret example cdylib not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("ok hunter2"),
        "the linked module resolved the configured key: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "the two doors must register one row");
}
