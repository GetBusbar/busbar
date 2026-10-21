// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TABLE IS LENT, NOT HELD (status row 82, D2; the ARCHITECT ruling on a6's review of #1406):
//! the kernel keeps no door table of its own, so two generations built from two tables in one
//! process each read only the table they were lent.
//!
//! RED before this change: the kernel held ONE process-wide set (`INSTALLED`, and its test twin, the
//! process registry), every generation and every config parse read it, and a second table could not
//! be installed at all — so the second generation below would have read the first's planes, and
//! the document that names one table's section would have parsed (or been refused) the same way
//! against both.

use super::*;
use crate::test_support::{neutral_fallback_plane, TestApp};

static ONE: PlaneDecl = neutral_sibling_decl("lent-one", "lent-one-section", "one");
static TWO: PlaneDecl = neutral_sibling_decl("lent-two", "lent-two-section", "two");

#[test]
fn two_apps_lent_two_tables_each_read_only_their_own() {
    let one = Doors::for_test(&[neutral_fallback_plane(), &ONE]);
    let two = Doors::for_test(&[neutral_fallback_plane(), &TWO]);
    let a = TestApp::new().doors(one).build();
    let b = TestApp::new().doors(two).build();

    // Each generation carries the table it was lent, and no other.
    assert_eq!(a.doors, one);
    assert_eq!(b.doors, two);
    assert!(a.doors.plane_decl_for("lent-one").is_some());
    assert!(a.doors.plane_decl_for("lent-two").is_none());
    assert!(b.doors.plane_decl_for("lent-two").is_some());
    assert!(b.doors.plane_decl_for("lent-one").is_none());

    // A document read against each: the section one table's door declares is carried for its
    // plane; against the other table no door declares it, so the frozen struct refuses it as the
    // unknown key 1.5.5 refused.
    let doc = "lent-one-section:\n  entry: {}\n";
    let parsed = crate::config::deploy_from_yaml_str(doc, a.doors)
        .expect("the first table's door declares `lent-one-section`");
    assert!(
        parsed.plane_raw.contains_key("lent-one-section"),
        "{:?}",
        parsed.plane_raw.keys().collect::<Vec<_>>()
    );
    let refused = crate::config::deploy_from_yaml_str(doc, b.doors)
        .expect_err("no door of the second table declares `lent-one-section`")
        .to_string();
    assert!(
        refused.contains("unknown field `lent-one-section`"),
        "{refused}"
    );
}

#[test]
fn a_table_folds_each_row_once_in_its_own_order() {
    // The test table is folded as the composition root folds its own: one row per key.
    let doors = Doors::for_test(&[&ONE, &TWO, &ONE]);
    let keys: Vec<_> = doors.plane_keys().collect();
    assert_eq!(keys, ["lent-one", "lent-two"]);
    assert!(Doors::NONE.decls().is_empty());
    assert_ne!(Doors::for_test(&[&ONE]), Doors::for_test(&[&TWO]));
}
