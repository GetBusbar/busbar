// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// The lint hooks: the exact symbol lists the source scan enforces.
//
// This file is DATA, not surface. Everything in it exists because Rust cannot express the rule: a
// hold has to be consumed by exactly one function, Rust has no linear types, so `std::mem::forget`
// will always compile. Rather than pretend otherwise, the rules the compiler cannot carry are
// written down in `lint_rules.txt` and the workspace's source scan enforces them. The scan is the
// enforcement; the data is the specification, and a test in this crate keeps it from going empty
// or stale.
//
// The scan's shape is deliberately dull: for each entry, a literal substring search over the Rust
// sources of the crates named by the entry's scope, with one reviewed allow-list of exceptions. No
// parsing, no cleverness, nothing that can be argued with in review.
//
// It lives under `fixtures/` rather than under `src/` because a plugin author never names any of
// it; it is included into the crate's test module and nowhere else.
//
// The rule DATA is not in this file. It is `lint_rules.txt` beside it (ARCHITECT ruling Q-GG2): the
// list has to spell the constructors it confines, and as Rust source those spellings were read by
// the construction gate's `token-sealed` scan as forged mints. As data the gate never walks, they
// are what they always were, a specification. This file keeps the types and the parser.

/// One rule the compiler cannot enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LintRule {
    /// The literal the scan looks for.
    pub symbol: &'static str,
    /// Where it is banned, or where it is the only thing allowed.
    pub scope: LintScope,
    /// Why, in one sentence, for the failure message.
    pub because: &'static str,
}

/// Where a rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintScope {
    /// The symbol may not appear anywhere in the workspace's kernel or unit crates.
    BannedEverywhere,
    /// The symbol may appear only in files whose path contains this fragment.
    ConfinedTo(&'static str),
}

/// The rule data, verbatim. See the module header for why it is not Rust source.
const DATA: &str = include_str!("lint_rules.txt");

/// The data's records, comments and blank lines skipped, each split into its ` | ` fields.
fn records() -> impl Iterator<Item = Vec<&'static str>> {
    DATA.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(" | ").map(str::trim).collect())
}

/// The rules of one list (`hold-escape` or `seal-site`), in file order.
fn list(name: &str) -> Vec<LintRule> {
    records()
        .filter(|f| f.first() == Some(&"rule") && f.get(1) == Some(&name))
        .map(|f| {
            assert_eq!(f.len(), 5, "a rule line has five fields: {f:?}");
            let scope = match f[2] {
                "banned" => LintScope::BannedEverywhere,
                other => LintScope::ConfinedTo(
                    other
                        .strip_prefix("confined:")
                        .unwrap_or_else(|| panic!("unknown scope {other:?}")),
                ),
            };
            LintRule {
                symbol: f[3],
                scope,
                because: f[4],
            }
        })
        .collect()
}

/// The ways a hold could be made to disappear without a posting. Every one of them compiles; none
/// of them is ever correct, because a hold that vanishes is money that vanishes.
pub fn hold_escapes() -> Vec<LintRule> {
    list("hold-escape")
}

/// The symbols that decide who may build a capability at all. Each is a crate boundary Rust cannot
/// police, so each is one audited name.
pub fn seal_sites() -> Vec<LintRule> {
    list("seal-site")
}

/// Everything the scan enforces, in one list.
pub fn all() -> impl Iterator<Item = LintRule> {
    hold_escapes().into_iter().chain(seal_sites())
}

/// The symbols the join test requires the rule list to keep naming.
pub fn expected() -> Vec<&'static str> {
    records()
        .filter(|f| f.first() == Some(&"expect"))
        .map(|f| {
            assert_eq!(f.len(), 2, "an expect line has two fields: {f:?}");
            f[1]
        })
        .collect()
}
