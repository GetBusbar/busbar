// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::both_ways::{dropped_third_party, row};
use crate::{LinkedPlugin, PluginRegistry};

#[test]
fn a_third_party_signature_is_a_different_row() {
    let door = crate::neutral_auth::door;
    let path = crate::neutral_auth::cdylib();
    let image = std::fs::read(path).expect("read the neutral auth image");
    let module = crate::neutral_auth::NAME;
    let manifest = LinkedPlugin::first_party_door("auth", module, "the-auth", door).manifest;
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(manifest.clone(), door)])
        .expect("neutral auth linked row");
    let mut third_party = manifest;
    third_party.publisher = "a-third-party".into();
    let dropped = dropped_third_party("neutral-auth", third_party, &image);
    let dropped_row = row(&dropped, module);
    assert!(!dropped_row.starts_with("no row"), "{dropped_row}");
    assert_ne!(
        row(&linked, module),
        dropped_row,
        "a third-party neutral auth row must not compare equal to the first-party one"
    );
}
