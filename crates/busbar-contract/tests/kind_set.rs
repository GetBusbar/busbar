// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed set of plugin kinds is exactly the seven DECISIONS #3 locks — and `Kind::ALL`, the
//! ground truth the `kind-isolation:truths` enum-variant assertion reads, reflects it faithfully.
//!
//! Auth is ONE kind: inbound-verify and outbound-sign are two OPERATIONS of it, not two kinds, so
//! there is no separate `egress-auth` variant.

use busbar_contract::Kind;

#[test]
fn the_kind_set_is_exactly_the_seven_locked_kinds() {
    assert_eq!(
        Kind::ALL.len(),
        7,
        "DECISIONS #3 locks the kind set at seven"
    );
    let names: Vec<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(
        names,
        [
            "plane",
            "transport",
            "auth",
            "store",
            "secret",
            "hook",
            "export"
        ],
    );
}

#[test]
fn there_is_no_separate_egress_auth_kind() {
    // No variant spells `egress-auth`; the outbound sign operation lives on `AuthScheme`, under the
    // one `Kind::Auth`.
    assert!(!Kind::ALL.iter().any(|k| k.name() == "egress-auth"));
    assert!(Kind::ALL.contains(&Kind::Auth));
}

#[test]
fn all_lists_every_variant_at_its_own_ordinal_and_display_matches_name() {
    for (i, k) in Kind::ALL.iter().enumerate() {
        assert_eq!(k.ordinal(), i);
        assert_eq!(k.to_string(), k.name());
    }
}
