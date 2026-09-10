// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOG'S OWN TEST, in its own file. An implementation file's length must measure ONE thing,
//! so the body lives here and `catalog.rs` carries the `#[path]` declaration.

use super::*;
#[test]
fn the_catalog_is_well_formed_and_every_code_is_namespaced() {
    let c = catalog();
    c.check().expect("well-formed");
    assert_eq!(c.entries.as_slice().len(), ENTRIES.len());
    for (code, _) in ENTRIES {
        assert!(code.starts_with("tokenmint."), "{code}");
        assert!(
            c.template(code, "de").is_some(),
            "{code} falls back to the default locale"
        );
    }
}
