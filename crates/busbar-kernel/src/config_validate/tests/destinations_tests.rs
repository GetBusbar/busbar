// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn transport_authority_is_not_trusted_as_a_url() {
    for authority in [
        "host:443/path",
        "user@host:443",
        "[::1]junk",
        "host:65536",
        "host:0",
        "host",
        "::1:443",
    ] {
        assert!(
            ProviderDestination {
                authority: authority.into(),
                secure: true,
                name: None
            }
            .host()
            .is_err(),
            "{authority}"
        );
    }
    for (authority, expected) in [
        ("[::1]:443", "::1"),
        ("0x7f000001:80", "127.0.0.1"),
        ("EXAMPLE.COM:443", "example.com"),
    ] {
        assert_eq!(
            ProviderDestination {
                authority: authority.into(),
                secure: false,
                name: None
            }
            .host()
            .unwrap(),
            expected
        );
    }
}
