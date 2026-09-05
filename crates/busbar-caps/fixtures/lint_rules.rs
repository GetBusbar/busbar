// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// The lint hooks: the exact symbol lists the source scan enforces.
//
// This file is DATA, not surface. Everything in it exists because Rust cannot express the rule: a
// hold has to be consumed by exactly one function, Rust has no linear types, so `std::mem::forget`
// will always compile. Rather than pretend otherwise, the rules the compiler cannot carry are
// written down here and the workspace's source scan reads them. The scan is the enforcement; this
// file is the specification, and a test in this crate keeps it from going empty or stale.
//
// The scan's shape is deliberately dull: for each entry, a literal substring search over the Rust
// sources of the crates named by the entry's scope, with one reviewed allow-list of exceptions. No
// parsing, no cleverness, nothing that can be argued with in review.
//
// It lives under `fixtures/` rather than under `src/` because a plugin author never names any of
// it; it is included into the crate's test module and nowhere else.

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

/// The ways a hold could be made to disappear without a posting. Every one of them compiles; none
/// of them is ever correct, because a hold that vanishes is money that vanishes.
pub const HOLD_ESCAPES: &[LintRule] = &[
    LintRule {
        symbol: "mem::forget",
        scope: LintScope::BannedEverywhere,
        because: "a forgotten hold is a unit that was admitted and never settled",
    },
    LintRule {
        symbol: "ManuallyDrop",
        scope: LintScope::BannedEverywhere,
        because: "the same as forgetting, spelled differently",
    },
    LintRule {
        symbol: "Box::leak",
        scope: LintScope::BannedEverywhere,
        because: "a leaked hold never reaches the exit path",
    },
    LintRule {
        symbol: "process::abort",
        scope: LintScope::BannedEverywhere,
        because: "aborting skips every exit path at once; the node drains instead",
    },
    LintRule {
        symbol: "AssertUnwindSafe",
        scope: LintScope::ConfinedTo("kernel/src/teller"),
        because: "it is what lets a hold cross a catch_unwind; the loop needs it in exactly one \
                  place and nothing else may use it",
    },
    LintRule {
        symbol: "JoinHandle::abort",
        scope: LintScope::BannedEverywhere,
        because: "an aborted task loses its unit's end; the sweep is the second exit, not abort",
    },
];

/// The symbols that decide who may build a capability at all. Each is a crate boundary Rust cannot
/// police, so each is one audited name.
pub const SEAL_SITES: &[LintRule] = &[
    LintRule {
        symbol: "KernelSeal::acquire_for_kernel",
        scope: LintScope::ConfinedTo("kernel/src"),
        because: "the seal is what mints every token; only the kernel may obtain one",
    },
    LintRule {
        symbol: "RecoveryToken",
        scope: LintScope::ConfinedTo("kernel/src/recovery"),
        because: "it materialises a hold from a journal record with no admission behind it",
    },
    LintRule {
        symbol: "HoldCell::take",
        scope: LintScope::ConfinedTo("kernel/src"),
        because: "there are exactly two take sites, the exit path and the sweep, and no third",
    },
];

/// Everything the scan enforces, in one list.
pub fn all() -> impl Iterator<Item = &'static LintRule> {
    HOLD_ESCAPES.iter().chain(SEAL_SITES.iter())
}
