// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot admission is muted in exactly one place: the boot build, which the boot narration covers.
//! Any other `after_boot_advice(..)` scope would silence a reload or an admin apply.

use proc_macro2::{Delimiter, TokenTree};

use crate::walk;

const CORE_SRC: &[&str] = &[
    "crates/busbar-kernel/src",
    "crates/busbar-contract/src",
    "crates/busbar/src",
    "crates/busbar-core-admin/src",
    "crates/busbar-core-oauth2/src",
    "crates/busbar-core-connector/src",
];

const THE_BOOT_BUILD: &str = "crates/busbar/src/root/startup_upgrade/continuation.rs";

#[test]
fn only_the_boot_build_runs_inside_the_boot_advice_scope() {
    let mut calls = Vec::new();
    for source in walk::production(CORE_SRC) {
        for item in walk::items(&source.file.items) {
            let toks = walk::tokens(item);
            for pair in toks.windows(2) {
                if let [TokenTree::Ident(name), TokenTree::Group(args)] = pair {
                    if name == "after_boot_advice" && args.delimiter() == Delimiter::Parenthesis {
                        calls.push(source.rel.clone());
                    }
                }
            }
        }
    }
    assert_eq!(
        calls,
        vec![THE_BOOT_BUILD.to_string()],
        "after_boot_advice( is called exactly once in production, by the boot build"
    );
}
