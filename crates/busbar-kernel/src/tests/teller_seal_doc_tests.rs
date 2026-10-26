// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAL ACCESSOR'S ENUMERATION IS THE TREE'S (item 299).
//!
//! The token factories on [`Kernel`](super::Kernel) each say they are kept where they are "so the
//! source scan that accounts for every mint sees this one too", and the one accessor that hands the
//! raw seal to other modules is where that accounting has to name what it lends it for. It named two
//! purposes and no tokens, while those two modules minted six-and-more — two of the tree's
//! production `WriteMoney` mints among them. The doc now states the count and the kinds per module;
//! this reads the minting module's real mints and holds the doc to them.

/// Every `Grant::<Kind>::mint(kernel.seal())` in one source file, by kind, in order.
fn seal_mints(src: &str) -> Vec<&str> {
    let mut kinds = Vec::new();
    for line in src.lines().filter(|l| !l.trim_start().starts_with("//")) {
        let mut rest = line;
        while let Some(at) = rest.find("Grant::<") {
            rest = &rest[at + "Grant::<".len()..];
            if let Some(end) = rest.find(">::mint(kernel.seal())") {
                if !rest[..end].contains(|c: char| !c.is_alphanumeric()) {
                    kinds.push(&rest[..end]);
                }
            }
        }
    }
    kinds
}

/// The `seal()` accessor's doc comment, joined into one line.
fn seal_doc() -> String {
    let src = include_str!("../teller.rs");
    let accessor = src
        .find("pub(crate) fn seal(&self) -> &KernelSeal")
        .expect("the seal accessor exists");
    let mut doc: Vec<&str> = src[..accessor]
        .lines()
        .rev()
        .skip(1)
        .map(str::trim)
        .take_while(|l| l.starts_with("///"))
        .map(|l| l.trim_start_matches('/').trim())
        .collect();
    doc.reverse();
    doc.join(" ")
}

#[test]
fn the_seal_accessor_names_every_token_minted_through_it() {
    // One module mints through the seal now: the node's sweep. Recovery, the other, went with the
    // second ledger (MONEY-DESIGN §4, PR-C).
    let tick = seal_mints(include_str!("../tick.rs"));
    let doc = seal_doc();
    let words = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    ];
    assert!(
        doc.contains(&format!("they mint {}", words[tick.len()])),
        "the seal accessor's doc must state the {} tokens minted through it; it reads: {doc}",
        tick.len()
    );
    let money = tick.iter().filter(|k| **k == "WriteMoney").count();
    assert!(
        doc.contains(&format!("{} of them `WriteMoney`", words[money])),
        "the doc must name the {money} WriteMoney mints; it reads: {doc}"
    );
    let (_, tick_doc) = doc
        .split_once("the node's sweep")
        .expect("the doc names the sweep's mints");
    for kind in &tick {
        assert!(
            tick_doc.contains(&format!("`{kind}`")),
            "tick mints `{kind}` through the seal and the doc does not name it: {tick_doc}"
        );
    }
}
