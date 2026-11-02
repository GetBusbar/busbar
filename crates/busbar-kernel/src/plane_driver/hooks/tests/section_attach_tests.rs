// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn the_section_scope_is_the_reserved_hooks_word() {
    assert_eq!(crate::hooks::SECTION_SCOPE, "hooks");
    assert!(busbar_contract::section::RESERVED_SECTION_KEYS.contains(&crate::hooks::SECTION_SCOPE));
}
