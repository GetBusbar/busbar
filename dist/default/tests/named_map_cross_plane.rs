// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use busbar_kernel::config::named_map::NamedMapSection;

fn register_planes() {
    linked::install();
}

#[test]
fn sections_holds_the_frozen_named_map_order_under_the_default_feature_set() {
    register_planes();
    let keys: Vec<&'static str> = NamedMapSection::sections()
        .iter()
        .map(|s| s.key())
        .collect();
    assert_eq!(
        keys,
        vec!["identity-providers", "export", "tools", "agents"],
        "sections() must yield the frozen 1.5.3 order so the router/OpenAPI surface stays \
         byte-identical"
    );
}
