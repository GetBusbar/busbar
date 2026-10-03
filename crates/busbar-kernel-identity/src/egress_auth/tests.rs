// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// The request-signing scheme of AWS's published worked example (`us-east-1`, `iam`) for an access
/// key id (`AKIDEXAMPLE` in the example), optionally with a temporary credential's session token.
fn example_signing_scheme(
    access_key_id: &'static str,
    session_token: Option<&'static str>,
) -> Scheme<'static> {
    Scheme::SigV4 {
        access_key_id,
        region: "us-east-1",
        service: "iam",
        session_token: session_token.map(SessionToken),
    }
}

// ── THE SHARED HEADER BUILDERS: one legality rule, two ways to present a key ─────────────────────

/// Keys a config system can hand the egress path, each with whether the `http` crate's
/// `HeaderValue::from_str` (the rule the dialects' shared builders judged a key by) admits it.
/// Tab is the case the unit's earlier `is_ascii_control` rule refused and the wire admitted.
const KEY_VECTORS: &[(&str, bool)] = &[
    ("sk-test-123", true),
    ("", true),
    ("sk\tkey", true),
    ("klucz-\u{142}-\u{e9}", true),
    ("sk\r\ninjected", false),
    ("sk\nkey", false),
    ("sk\u{0}key", false),
    ("sk\u{1}key", false),
    ("sk\u{7f}key", false),
];

/// The legality rule is the `http` crate's `HeaderValue` rule — the rule a sent header is actually
/// held to — written out as its table over every ASCII byte: the C0 controls and DEL are refused
/// except horizontal tab, everything else (and every non-ASCII byte) is admitted. So the unit never
/// omits a header the wire would carry, nor builds one the wire would refuse.
#[test]
fn header_value_rule_is_the_http_crate_rule() {
    for b in 0u8..=0x7F {
        let refused = (b < 0x20 && b != b'\t') || b == 0x7F;
        let s = format!("k{}k", b as char);
        assert_eq!(is_legal_header_value(&s), !refused, "byte {b:#04x}");
    }
    for &(key, legal) in KEY_VECTORS {
        assert_eq!(is_legal_header_value(key), legal, "key {key:?}");
    }
}

/// A logged scheme shows that a session token is present and never the token itself.
#[test]
fn a_logged_scheme_redacts_its_session_token() {
    let printed = format!(
        "{:?}",
        example_signing_scheme("AKIDEXAMPLE", Some("SESSIONTOKEN"))
    );
    assert!(!printed.contains("SESSIONTOKEN"), "{printed}");
    assert!(printed.contains("<redacted>"), "{printed}");
}
