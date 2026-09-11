// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT'S PLANE INSTALLER, proven.
//!
//! Split out of `root/plane_install.rs` under `#[path]` for the reason every other root test file
//! is: an implementation file that carries its own test bodies measures two things with one length.

use busbar_contract::plane::PlaneDeclaration;

const fn decl(key: &'static str, config_section: &'static str) -> PlaneDeclaration {
    PlaneDeclaration {
        key,
        fallback: false,
        config_section,
        scope_kinds: &["thing"],
        subject_noun: "thing",
        admin_noun: "thing",
        audit_kind: "thing",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        operator_routes: &[],
    }
}
const ONE: PlaneDeclaration = decl("one", "ones");
const TWO: PlaneDeclaration = decl("two", "twos");
const NO_SECTION: PlaneDeclaration = decl("three", "");
const NO_SCOPES: PlaneDeclaration = PlaneDeclaration {
    scope_kinds: &[],
    ..decl("four", "fours")
};

/// TWO PLANES THROUGH ONE INSTALL. The whole point of the pair form: the root hands both halves
/// of both planes across in one call, and the set is judged as a set — and the contract's fold
/// over the same two declarations yields both keys, in the order the root installed them.
#[test]
fn two_planes_go_through_one_install_and_both_arrive() {
    assert_eq!(super::judge_one(&ONE, "one"), Ok(()));
    assert_eq!(super::judge_one(&TWO, "two"), Ok(()));
    let fold = busbar_contract::plane::registry::merged_boot_plane_decls(&[ONE, TWO], &[]);
    let keys: Vec<&str> = fold.decls.iter().map(|d| d.key).collect();
    assert_eq!(keys, ["one", "two"]);
    assert!(fold.skipped.is_empty(), "{:?}", fold.skipped);
}

/// A DECLARATION MISSING A FACT DOES NOT COMPOSE, and the refusal names the plane and the fact.
#[test]
fn a_declaration_missing_a_fact_is_refused_and_names_it() {
    let err =
        super::judge_one(&NO_SECTION, "three").expect_err("an empty config_section is not a plane");
    assert!(
        err.contains("`three`") && err.contains("config_section"),
        "{err}"
    );

    let err = super::judge_one(&NO_SCOPES, "four")
        .expect_err("a plane no grant can be written over is not a plane");
    assert!(
        err.contains("`four`") && err.contains("scope kinds"),
        "{err}"
    );
}

/// The same declarations with the missing fact supplied pass, so the test above measures the
/// missing fact and not the guard refusing whatever it is handed.
#[test]
fn the_same_declarations_complete_are_accepted() {
    assert_eq!(super::judge_one(&decl("three", "threes"), "three"), Ok(()));
    assert_eq!(super::judge_one(&decl("four", "fours"), "four"), Ok(()));
}

/// A PAIR WHOSE HALVES NAME DIFFERENT PLANES is refused, naming both — the join is by key, so
/// this is the failure that would otherwise be silent.
#[test]
fn a_pair_whose_halves_name_different_planes_is_refused() {
    let err = super::judge_one(&ONE, "two").expect_err("one's facts, two's hooks");
    assert!(err.contains("`one`") && err.contains("`two`"), "{err}");
}

/// INSTALL BEFORE FIRST READ, enforced. The only test in this binary that calls
/// [`super::install_planes`], deliberately: it is a write to the process slot, and a second call
/// anywhere else here would make this test's outcome depend on execution order. The read is
/// forced first so the install has something to refuse to follow.
#[test]
#[should_panic(expected = "install_planes called after the plane list was first read")]
fn install_planes_after_first_read_panics() {
    let _ = busbar_contract::plane::registry::plane_decls();
    super::install_planes(&[]);
}
