// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reserved principal ids.

use crate::principal::id_is_reserved;

/// Both reserved prefixes are reserved, bare or followed by anything; an id that merely contains
/// one, or spells it in another case, is not.
#[test]
fn the_reserved_prefixes_and_only_they_are_reserved() {
    for id in ["group:", "group:acme", "vk_", "vk_deadbeefdeadbeef"] {
        assert!(id_is_reserved(id), "{id} is reserved");
    }
    for id in [
        "",
        "admin",
        "anonymous",
        "user:group:acme",
        "idp:vk_1",
        "VK_1",
        "Group:acme",
    ] {
        assert!(!id_is_reserved(id), "{id} is not reserved");
    }
}
