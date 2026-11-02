// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::VirtualKey;

#[test]
fn an_explicit_empty_scope_list_sees_no_pool() {
    let mut key = VirtualKey {
        id: "vk_empty_scopes".to_string(),
        enabled: true,
        ..Default::default()
    };
    key.allowed_scopes = Some(Vec::new());
    assert!(
        !crate::governance::pool_allowed(&key, "any-pool"),
        "an explicit empty list is no scopes at all, never all pools"
    );
    key.allowed_scopes = None;
    assert!(
        crate::governance::pool_allowed(&key, "any-pool"),
        "only an omitted list is a wildcard"
    );
}
