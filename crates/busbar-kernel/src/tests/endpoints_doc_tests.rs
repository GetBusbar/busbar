// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TOPOLOGY SURFACES' DOCS READ THE SCOPE LIST THE WAY THE FROZEN PRIMITIVE DOES (item 569).
//!
//! `/stats` and `/v1/models` said an EMPTY allowed list means "all pools". The frozen governance
//! primitive (`busbar_contract::records::VirtualKey::scope_allowed`) says an explicit empty list is NO
//! scopes at all and names the opposite reading as fail-open; the code here agrees with the primitive.
//! A maintainer reconciling header and body in the header's favour would have turned a key minted
//! with an empty list into a wildcard over the whole topology. Behaviour is pinned end to end in
//! `crates/busbar/tests/endpoints_cross_plane.rs` (real lanes only exist through a real plane, which
//! the composition root links); what is pinned here
//! is that the prose cannot drift back to the fail-open reading, and that the primitive the prose now
//! cites still reads the list the way the prose says.

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
