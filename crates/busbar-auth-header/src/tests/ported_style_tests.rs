// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A keyless member's binding, carried over from the previous release's auth-style test: on the
//! door path a member's upstream credential is presented by this mechanism's binding, opened once
//! with the member's credential, so its own header is built here or nowhere.

use super::*;

/// Ports legacy `auth_style_tests.rs::test_keyless_lane_sends_no_auth_header`: an empty credential
/// (a provider declared `api_key: none`) presents no auth header at all, for every header style,
/// never `Authorization: Bearer ` with nothing after it and never an empty `api-key:`; the binding
/// is built once, at open, so nothing frozen there can carry one either. A real credential is
/// unaffected.
#[test]
fn a_keyless_member_presents_no_auth_header_in_any_style() {
    for style in [BEARER, API_KEY, X_GOOG_API_KEY] {
        for credential in [None, Some(&b""[..])] {
            let mut notes = Vec::new();
            let binding = open_binding(style, credential, Some(&b"{}"[..]), &mut notes)
                .unwrap_or_else(|_| panic!("a keyless {style} binding opens"));
            assert!(
                binding.own().is_empty(),
                "an empty credential presents no auth header (style {style}, {credential:?})"
            );
            assert!(notes.is_empty(), "keyless is not a fault (style {style})");
        }
    }
    let mut notes = Vec::new();
    let binding = open_binding(
        BEARER,
        Some(&b"SECRETKEY"[..]),
        Some(&b"{}"[..]),
        &mut notes,
    )
    .unwrap_or_else(|_| panic!("a keyed binding opens"));
    assert_eq!(
        binding.own().len(),
        1,
        "a real credential still presents its header"
    );
}
