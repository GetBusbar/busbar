// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-oauth2/src/routes.rs` — the host the consent screen names.

use super::host_of;

/// The consent screen names the host the browser will contact. RED on the reader that split only at
/// `/`: it named `trusted.example` for `https://evil.example\@trusted.example/cb`, while the browser
/// reads the `\` as the end of the authority and sends the code to `evil.example`.
#[test]
fn the_consent_host_is_the_host_the_browser_dials() {
    for (uri, host) in [
        ("https://evil.example\\@trusted.example/cb", "evil.example"),
        ("https://client.example@evil.example/cb", "evil.example"),
        ("https://%65vil.example/cb", "evil.example"),
        ("https://trusted.example/cb", "trusted.example"),
        ("http://127.0.0.1:9999/cb", "127.0.0.1:9999"),
        ("https://[::1]:8443/cb", "[::1]:8443"),
        ("not a uri", ""),
    ] {
        assert_eq!(host_of(uri), host, "{uri}");
    }
}
