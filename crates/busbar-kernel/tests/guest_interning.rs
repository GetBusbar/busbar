// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Route literals are interned once: a second build of the same guest list (a reload with the same
//! routes) adds nothing to the interner. This file holds one test so no other build in the process
//! moves the table while it is counted.

use busbar_contract::abi::transport::route::{
    FIELD_VALUE_PREFIX, METHOD_ANY, PATH_EXACT, PATH_PATTERN,
};
use busbar_kernel::guest::{interned_counts, Claimant, GuestList, Line, LineAuth, Route};

fn lines() -> Vec<Line> {
    let line = |who: &str, form: u32, path: &str, fields: Vec<(u32, String, Vec<u8>)>| Line {
        route: Route {
            methods: METHOD_ANY,
            path_form: form,
            path: path.into(),
            fields,
            rung: 0,
        },
        claimant: Claimant::Plane(who.into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
    };
    vec![
        line("a", PATH_EXACT, "/intern/exact", Vec::new()),
        line("b", PATH_PATTERN, "/intern/{id}/tail/{*rest}", Vec::new()),
        line(
            "c",
            PATH_EXACT,
            "/intern/pred",
            vec![(FIELD_VALUE_PREFIX, "x-intern".into(), b"pfx".to_vec())],
        ),
    ]
}

/// RED without the kernel's one interner: a second build of the same list grows its table by zero.
#[test]
fn a_second_build_of_the_same_guest_list_interns_nothing_new() {
    GuestList::seal(lines()).unwrap();
    let after_first = interned_counts();
    GuestList::seal(lines()).unwrap();
    GuestList::seal(lines()).unwrap();
    assert_eq!(interned_counts(), after_first, "a reload leaks nothing new");
    assert!(after_first.0 > 1 && after_first.1 >= 1);
}
