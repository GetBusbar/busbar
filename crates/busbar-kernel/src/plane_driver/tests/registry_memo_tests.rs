// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The process plane list must be the fold of the registration set that is actually installed: two
//! distinct sets of equal length never alias (item 117 — 8 `units_llm` tests once failed whenever the
//! `plane_decisions` tests ran first, even single-threaded).

use super::*;
use crate::test_support::planes::TestRegistryIsolation;

static ONE: PlaneDecl =
    crate::plane_driver::dispatch::neutral_sibling_decl("memo-one", "memo-one-section", "one");
static TWO: PlaneDecl =
    crate::plane_driver::dispatch::neutral_sibling_decl("memo-two", "memo-two-section", "two");

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
