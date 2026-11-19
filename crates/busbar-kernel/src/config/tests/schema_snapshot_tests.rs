// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `advanced:` section against `config-schema.snapshot.json`: every key the typed
//! configuration accepts is in the snapshot, and every key in the snapshot is accepted.
//!
//! The snapshot's header names a generator and a gate (`scripts/config-schema.py`,
//! `cargo xtask gate config-schema`) that are not in this tree, so nothing else ties the file to
//! the types. This test covers the section it names, reading the typed side from serde itself:
//! a `deny_unknown_fields` struct lists every key it accepts when it refuses an unknown one.

use std::collections::BTreeSet;

use busbar_contract::json::JsonContainerTrait as _;

use super::*;

const SNAPSHOT: &str = include_str!("../config-schema.snapshot.json");

fn snapshot_keys(type_name: &str) -> BTreeSet<String> {
    let snapshot: busbar_contract::json::Value =
        busbar_contract::json::parse_str(SNAPSHOT).expect("the snapshot parses");
    snapshot["types"][type_name]["fields"]
        .as_object()
        .unwrap_or_else(|| panic!("the snapshot has no struct {type_name}"))
        .iter()
        .map(|(key, _)| key.to_string())
        .collect()
}

fn accepted_keys<T: serde::de::DeserializeOwned>() -> BTreeSet<String> {
    let error = busbar_contract::yaml::from_str::<T>("no_such_key_for_the_probe: 1\n")
        .err()
        .expect("an unknown key is refused")
        .to_string();
    let (_, listed) = error
        .split_once(", expected ")
        .unwrap_or_else(|| panic!("serde lists the accepted keys: {error}"));
    listed
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_advanced_section_and_the_schema_snapshot_name_the_same_keys() {
    assert_eq!(
        accepted_keys::<AdvancedCfg>(),
        snapshot_keys("AdvancedCfg"),
        "AdvancedCfg and config-schema.snapshot.json disagree"
    );
    assert_eq!(
        accepted_keys::<ResponseHeadersCfg>(),
        snapshot_keys("ResponseHeadersCfg"),
        "ResponseHeadersCfg and config-schema.snapshot.json disagree"
    );
}
