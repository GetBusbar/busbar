// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R34 over core's production source, and the forms it must refuse and keep (the probe table of
//! OBSERVABILITY-HOT-PATH §2.7).

use crate::{escapes, walk};

#[test]
fn no_disallowed_lint_escape_is_wider_than_one_site_and_one_lint() {
    let found: Vec<String> = walk::production(&["crates"])
        .iter()
        .flat_map(|s| escapes::refusals(&s.rel, &s.file))
        .collect();
    assert!(found.is_empty(), "{}", found.join("\n"));
}

fn refused(src: &str) -> Vec<String> {
    escapes::refusals("planted.rs", &syn::parse_file(src).expect("parses"))
}

#[test]
fn every_tree_wide_or_group_escape_is_refused() {
    for src in [
        "#[allow(clippy::disallowed_methods)] fn f() {}",
        "fn f() { #[allow(clippy::disallowed_macros)] let x = 1; }",
        "#[allow(clippy::style)] mod m {}",
        "#[allow(clippy::all)] mod m {}",
        "#[cfg_attr(not(test), allow(clippy::all))] mod m {}",
        "#[cfg_attr(unix, cfg_attr(test, allow(clippy::disallowed_types)))] struct S;",
        "#[expect(clippy::style, reason = \"r\")] mod m {}",
        "fn f() { #[expect(clippy::all, reason = \"r\")] let x = 1; }",
        "#[expect(clippy::disallowed_methods, reason = \"r\")] mod m {}",
        "#[expect(clippy::disallowed_methods, reason = \"r\")] fn f() {}",
        "struct S; #[expect(clippy::disallowed_methods, reason = \"r\")] impl S {}",
        "#[expect(clippy::disallowed_macros, reason = \"r\")] trait T {}",
        "struct S; impl S { #[expect(clippy::disallowed_methods, reason = \"r\")] fn f() {} }",
        "trait T { #[expect(clippy::disallowed_methods, reason = \"r\")] fn f() {} }",
        "#![expect(clippy::disallowed_methods, reason = \"r\")]",
        "mod m { #![expect(clippy::disallowed_types, reason = \"r\")] }",
        "#[cfg_attr(test, expect(clippy::disallowed_methods, reason = \"r\"))] fn f() {}",
    ] {
        assert_eq!(refused(src).len(), 1, "{src}: {:?}", refused(src));
    }
}

#[test]
fn a_one_site_one_lint_escape_and_unrelated_lints_are_kept() {
    for src in [
        "fn f() { #[expect(clippy::disallowed_methods, reason = \"cold\")] let x = g(); }",
        "#[expect(clippy::disallowed_types, reason = \"cold\")] static S: u8 = 0;",
        "#[expect(clippy::disallowed_methods, reason = \"cold\")] const C: u8 = 0;",
        "struct S { #[expect(clippy::disallowed_types, reason = \"cold\")] f: u8 }",
        "#[allow(warnings)] mod m {}",
        "#[allow(clippy::restriction)] mod m {}",
        "#[allow(clippy::too_many_arguments)] fn f() {}",
        "#[expect(dead_code, reason = \"r\")] mod m {}",
    ] {
        assert!(refused(src).is_empty(), "{src}: {:?}", refused(src));
    }
}
