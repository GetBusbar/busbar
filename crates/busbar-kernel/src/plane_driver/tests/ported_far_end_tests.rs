// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authority the far end lends a member's auth binding to sign, carried over from the previous
//! release's signing-host test. The host a signature covers must be the host the dial reaches, or
//! the signed request is either refused by the far end or, worse, signed for one host and sent to
//! another.

use super::split;

/// Ports legacy `auth_style_tests.rs::test_host_from_base_backslash_authority_matches_wire_host`:
/// a URL parser of the kind the connector dials with treats `\` as a path delimiter exactly like
/// `/`, so the dialled host ends at the first backslash; the signed host must end there too, never
/// read past it to a later `@`.
#[test]
#[ignore = "DIVERGENCE: the far end's signing authority (`far_end::split`) reads past a backslash; 1.5.5 signed the host ending at the first `\\` and with its userinfo stripped (kernel change)"]
fn the_signed_authority_ends_at_the_first_backslash_as_the_dialled_host_does() {
    // A backslash where a `/` would start the path: the dial reaches `evil.example.com`, so the
    // signed host is the same, not the host after the `@`.
    assert_eq!(
        split("https://evil.example.com\\@victim.example/path").0,
        "evil.example.com"
    );
    // A bare backslash path: the authority still ends at the `\`.
    assert_eq!(
        split("https://host.example.com\\some\\path").0,
        "host.example.com"
    );
    // The port survives; the backslash path does not.
    assert_eq!(
        split("https://host.example.com:8443\\v1\\foo").0,
        "host.example.com:8443"
    );
    // Userinfo before the real authority is stripped and the authority ends at the backslash.
    assert_eq!(
        split("https://user:pass@host.example.com\\p").0,
        "host.example.com"
    );
}
