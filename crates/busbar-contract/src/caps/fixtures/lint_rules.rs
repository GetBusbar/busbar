// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors






















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

pub fn hold_escapes() -> Vec<LintRule> {
    list("hold-escape")
}

/// The symbols that decide who may build a capability at all. Each is a crate boundary Rust cannot

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
