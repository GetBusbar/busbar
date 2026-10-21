// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The named-map PUT's structural refusals, as 1.5.5 worded them on the wire.

use super::*;
use busbar_kernel::config::named_map::NamedMapSection;

fn refusal(section: NamedMapSection) -> String {
    match validate_definition(
        busbar_kernel::plane_driver::doors::Doors::NONE,
        section,
        "x",
        &serde_json::json!("not an object"),
    ) {
        Err(AdminError::Validation(m)) => m,
        other => panic!("a non-object definition is refused: {other:?}"),
    }
}

/// A NON-OBJECT DEFINITION IS REFUSED IN 1.5.5's WORDS (Q128 core-admin u19, MEDIUM): for a
/// section whose entries name a `module:`, the 400 message is 1.5.5's sentence byte for byte
/// (v1.5.5 crates/busbar/src/admin/v1/json/named_map.rs:695). RED before the fix: the sentence had
/// lost its `({"module": …})` tail.
#[test]
fn a_non_object_definition_is_refused_in_1_5_5_words() {
    assert_eq!(
        refusal(NamedMapSection::IdentityProviders),
        format!(
            "a {} definition must be an object (`{{\"module\": …}}`)",
            NamedMapSection::IdentityProviders
                .singular(busbar_kernel::plane_driver::doors::Doors::NONE)
        )
    );
    assert_eq!(
        refusal(NamedMapSection::Export),
        format!(
            "a {} definition must be an object (`{{\"module\": …}}`)",
            NamedMapSection::Export.singular(busbar_kernel::plane_driver::doors::Doors::NONE)
        )
    );
}
