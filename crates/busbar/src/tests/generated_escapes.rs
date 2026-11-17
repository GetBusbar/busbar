// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R34 `no-tree-escape` over the binary's two generated sources (`main.rs` includes them from
//! `OUT_DIR`), which core's source rules cannot read from `busbar-contract`.

#[test]
fn the_generated_link_sources_hold_no_tree_wide_lint_escape() {
    for (rel, text) in [(
        "OUT_DIR/linked.rs",
        include_str!(concat!(env!("OUT_DIR"), "/linked.rs")),
    )] {
        let file = syn::parse_file(text).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let found = crate::source_escapes::refusals(rel, &file);
        assert!(found.is_empty(), "{}", found.join("\n"));
    }
}
