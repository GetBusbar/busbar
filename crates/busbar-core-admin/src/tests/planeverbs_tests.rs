// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared trust verb surface. The mounted behaviour of each plane's verbs is driven over the
//! REAL router where it lives (each plane crate's own `tests/adminverbs_tests.rs`).

use super::*;

/// A LOOKUP THAT RESOLVED IS PASSED STRAIGHT THROUGH. The shared rule decides the refusal and
/// nothing else; it never inspects, rewrites or re-validates what the plane found.
#[test]
fn a_resolved_lookup_is_returned_untouched() {
    let found =
        registered(|| Some(("entry", "cfg"))).expect("a lookup that resolved must not be refused");
    assert_eq!(found, ("entry", "cfg"));
}

// `the_admin_route_table_method_path_scope_is_byte_identical`, the not-found wording and the audit
// naming are driven over the REAL linked planes, so they live in the composition root
// (`crates/busbar/tests/admin_planeverbs_cross_plane.rs`): core names zero plane types, its tests
// included, and this crate links no plane served through its door.
