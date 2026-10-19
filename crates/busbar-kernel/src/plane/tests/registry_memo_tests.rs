// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test-surface plane-list memo (`TEST_MEMO`) must resolve against the registration set that is
//! actually installed. It used to key on the set's SIZE, so two distinct sets of equal length aliased:
//! whichever was folded first was handed back for the other (item 117 — 8 `units_llm` tests failed
//! whenever the `plane_decisions` tests ran first, even single-threaded).

use super::*;

static ONE: PlaneDecl = crate::plane::neutral_sibling_decl("memo-one", "memo-one-section", "one");
static TWO: PlaneDecl = crate::plane::neutral_sibling_decl("memo-two", "memo-two-section", "two");

fn keys() -> Vec<&'static str> {
    plane_decls().iter().map(|d| d.key).collect()
}

#[test]
fn two_distinct_registration_sets_of_equal_size_do_not_alias() {
    {
        let _reg = TestRegistryIsolation::seeded(&[&ONE]);
        let k = keys();
        assert!(k.contains(&"memo-one"), "set {{ONE}} folds ONE: {k:?}");
        assert!(
            !k.contains(&"memo-two"),
            "set {{ONE}} does not fold TWO: {k:?}"
        );
    }
    {
        // Same size as the set before it, different plane: must NOT be served the {ONE} fold.
        let _reg = TestRegistryIsolation::seeded(&[&TWO]);
        let k = keys();
        assert!(
            k.contains(&"memo-two"),
            "set {{TWO}} folds TWO, not the equal-size {{ONE}} fold: {k:?}"
        );
        assert!(
            !k.contains(&"memo-one"),
            "set {{TWO}} does not fold ONE: {k:?}"
        );
    }
    {
        // Back to the first set: the fold follows the set again, whichever was read last.
        let _reg = TestRegistryIsolation::seeded(&[&ONE]);
        let k = keys();
        assert!(k.contains(&"memo-one") && !k.contains(&"memo-two"), "{k:?}");
    }
}

#[test]
fn a_re_read_of_one_set_returns_the_one_leaked_fold() {
    let _reg = TestRegistryIsolation::seeded(&[&ONE, &TWO]);
    let a = plane_decls();
    let b = plane_decls();
    assert!(std::ptr::eq(a, b), "one set folds and leaks once");
}

// THE CARD SIGNER IS FOUND BY ITS DECLARED FACT, NOT BY A SECTION NAME (arch u32; #49,
// BUSBAR-1.6.0.md l.2235). A plane under any section that states a card-signing domain is the
// signer; a second declarer leaves the host signing nothing.
static SIGNER: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        card_signing_domain: Some("planted-card-domain"),
        card_kid_prefix: Some("planted-"),
        ..crate::plane::neutral_sibling_decl("card-signer", "not-a-known-section", "signer")
            .declaration
    },
    ..crate::plane::neutral_sibling_decl("card-signer", "not-a-known-section", "signer")
};
static OTHER_SIGNER: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        card_signing_domain: Some("planted-other-domain"),
        card_kid_prefix: Some("other-"),
        ..crate::plane::neutral_sibling_decl("card-signer-2", "another-section", "signer")
            .declaration
    },
    ..crate::plane::neutral_sibling_decl("card-signer-2", "another-section", "signer")
};

#[test]
fn the_card_signer_is_the_plane_stating_a_signing_domain_under_any_section() {
    let found = card_signing_decl_of(&[&ONE, &SIGNER, &TWO]).map(|d| d.key);
    assert_eq!(found, Some("card-signer"));
    assert_eq!(card_signing_decl_of(&[&ONE, &TWO]).map(|d| d.key), None);
}

#[test]
fn two_planes_stating_a_signing_domain_sign_nothing() {
    assert_eq!(
        card_signing_decl_of(&[&SIGNER, &OTHER_SIGNER]).map(|d| d.key),
        None
    );
}
