// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Boot admission is muted nowhere in production. The boot build used to run inside an
//! `after_boot_advice(..)` scope (UPG-A12's quiet gate plus one narration); that design was dropped
//! for one semantic pass per boot, inside the application build after the export sinks open
//! (DROPPED-IN-CONSOLIDATION: fix/upg-a12-neutrality). Any `after_boot_advice(..)` scope would now
//! silence a boot, a reload or an admin apply that no narration covers.

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

#[test]
fn no_production_code_runs_inside_the_boot_advice_scope() {
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
        Vec::<String>::new(),
        "after_boot_advice( is called nowhere in production: boot judges once, inside the build"
    );
}
