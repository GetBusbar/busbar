// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TOPOLOGY SURFACES' DOCS READ THE SCOPE LIST THE WAY THE FROZEN PRIMITIVE DOES (item 569).
//!
//! `/stats` and `/v1/models` said an EMPTY allowed list means "all pools". The frozen governance
//! primitive (`busbar_contract::records::VirtualKey::scope_allowed`) says an explicit empty list is NO
//! scopes at all and names the opposite reading as fail-open; the code here agrees with the primitive.
//! A maintainer reconciling header and body in the header's favour would have turned a key minted
//! with an empty list into a wildcard over the whole topology. Behaviour is pinned end to end in
//! `tests/endpoints_cross_plane.rs` (real lanes only exist through a real plane); what is pinned here
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

#[test]
fn the_docs_never_read_an_empty_list_as_all_pools() {
    let src = include_str!("../endpoints.rs");
    let prose = src
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for fail_open in [
        "empty `allowed_pools` (or",
        "means \"all pools\"",
        "or empty `allowed_pools`",
        "non-empty `allowed_pools`",
    ] {
        assert!(
            !prose.contains(fail_open),
            "endpoints.rs still reads the scope list fail-open: {fail_open:?}"
        );
    }
    assert!(
        !prose.contains("allowed_pools"),
        "the field is `allowed_scopes`; a doc naming `allowed_pools` describes a field the key lacks"
    );
}
