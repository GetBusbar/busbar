// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code for `auth::sight_redirect`: the text of a redirect core did not follow, spelled only
//! when a card fetch is answered with one.

/// Core's text for a redirect it did not follow, byte for byte (§12.14).
#[cold]
#[inline(never)]
pub(crate) fn not_followed_text(from: &str, to: &str, upstream: &str) -> String {
    format!(
        "redirect from {from} to {to} not followed: busbar 1.6 follows only same-origin redirects when \
         fetching an agent card; set `upstreams.{upstream}.url` to the card's origin"
    )
}
