// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::named_map::NamedMapSection;

fn refusal(section: NamedMapSection) -> String {
    match validate_definition(section, "x", &serde_json::json!("not an object")) {
        Err(AdminError::Validation(m)) => m,
        other => panic!("a non-object definition is refused: {other:?}"),
    }
}

#[test]
fn a_non_object_definition_is_refused_in_1_5_5_words() {
    assert_eq!(
        refusal(NamedMapSection::IdentityProviders),
        format!(
            "a {} definition must be an object (`{{\"module\": …}}`)",
            NamedMapSection::IdentityProviders.singular()
        )
    );
    assert_eq!(
        refusal(NamedMapSection::Export),
        format!(
            "a {} definition must be an object (`{{\"module\": …}}`)",
            NamedMapSection::Export.singular()
        )
    );
}
