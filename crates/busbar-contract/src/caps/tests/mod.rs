// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The runtime half of the proof that needs no token. The compile-time half is the compile-fail
//! fixtures in the module documentation; what is left over is what only a running program can show.
//! Every runtime proof that has to MINT a token to run — that the cell is a state machine, that a
//! hold is taken once, that an accrual is sealed to its parent — lives in the kernel
//! (`busbar-kernel/src/tests/caps_tests/`), because a token constructor is spelled only there
//! (construction `token-sealed`). What stays here reads the closed vocabularies, the canary and the
//! lint data, none of which takes a seal.

use crate::caps::*;

/// The lint rule data. It is a proof, not surface: no plugin, unit or kernel path names it, so it
/// lives beside the crate rather than inside it and is pulled in here for the test that keeps it
/// from going empty or stale. The records themselves are `fixtures/lint_rules.txt`.
mod lint {
    include!("../fixtures/lint_rules.rs");
}

/// The renderings every one of these types hand-rolls, read back — including the two that carry
/// something they are not allowed to say.
///
/// This module now lives at `src/tests/mod.rs`, so its children resolve beside it in `src/tests/`
/// by the ordinary directory-module rule — no `#[path]` needed to keep them classified as the proof
/// they are.
mod what_the_record_reads;

/// The posting's arithmetic at the edges: the width the priced total does not share with the
/// reservation, the line between spending the reservation and spending past it, and a unit that
/// runs past the end more than once.
mod the_posting_arithmetic;

/// Where a reported quantity came from, and the three questions the crate asks about it.
mod what_the_usage_report_says;

/// The take-site count the documentation states, against the kernel's own source (items 315, 320,
/// 326).
mod take_site_census;

/// The crate's honesty table names only types that exist (items 319, 327).
mod honesty_table;

/// Every implementor of the sealed plugin seal trait, against the minter's documentation (item 329).
mod seal_implementors;

/// Whether the kernel keeps this step's token to itself, read off the step markers' own
/// `KERNEL_OWNED` constants rather than off a second runtime table.
///
/// The exhaustive match is the proof's totality check: a step added to `StepName` stops this file
/// compiling until its marker is named here.
fn kernel_owned_marker(name: StepName) -> bool {
    match name {
        StepName::Arrival => <Arrival as Step>::KERNEL_OWNED,
        StepName::Decode => <Decode as Step>::KERNEL_OWNED,
        StepName::Authenticate => <Authenticate as Step>::KERNEL_OWNED,
        StepName::Verify => <Verify as Step>::KERNEL_OWNED,
        StepName::Approve => <Approve as Step>::KERNEL_OWNED,
        StepName::Admit => <Admit as Step>::KERNEL_OWNED,
        StepName::Route => <Route as Step>::KERNEL_OWNED,
        StepName::Meter => <Meter as Step>::KERNEL_OWNED,
        StepName::Audit => <Audit as Step>::KERNEL_OWNED,
        StepName::Encode => <Encode as Step>::KERNEL_OWNED,
    }
}

#[test]
fn the_ten_steps_are_in_order_and_three_belong_to_the_kernel() {
    assert_eq!(StepName::ALL.len(), 10);
    // The order itself, written out. Sorting the list and comparing it to itself only says the list
    // agrees with the derived `Ord`, and the derived `Ord` is the declaration order — so a pair of
    // steps declared the wrong way round satisfies that check and moves the under-hold line, which
    // is the comparison that decides whether a refusal was charged.
    assert_eq!(
        StepName::ALL,
        [
            StepName::Arrival,
            StepName::Decode,
            StepName::Authenticate,
            StepName::Verify,
            StepName::Approve,
            StepName::Admit,
            StepName::Route,
            StepName::Meter,
            StepName::Audit,
            StepName::Encode,
        ],
        "the ten steps, in the one order the loop calls them"
    );
    let mut sorted = StepName::ALL;
    sorted.sort();
    assert_eq!(sorted, StepName::ALL, "the list is already in loop order");

    // Who owns a step's token is the marker's own constant — the production spelling, read by the
    // teller when it decides whether to lend the token out. The list of three is the proof's, not a
    // second runtime table on the crate's surface that could drift from the constants.
    let kernel_owned: Vec<_> = StepName::ALL
        .iter()
        .filter(|s| kernel_owned_marker(**s))
        .copied()
        .collect();
    assert_eq!(
        kernel_owned,
        vec![StepName::Arrival, StepName::Decode, StepName::Encode]
    );

    // The marker's constant and the runtime name agree, for every step.
    assert_eq!(<Admit as Step>::NAME, StepName::Admit);

    // Under-hold is a comparison, and it starts strictly after the door.
    assert!(!StepName::Admit.under_hold());
    assert!(StepName::Route.under_hold());
    assert!(StepName::Audit.under_hold());
}

#[test]
fn every_way_a_unit_can_end_names_a_step_or_deliberately_does_not() {
    // The three that stop AT a step say which; the two that cut a unit short do not, because being
    // aborted or completing is a fact about the unit, not about a step.
    let names_a_step = [
        Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
        Outcome::Failed(StepName::Route, ReasonCode::PlanePanic),
        Outcome::TimedOut(StepName::Meter),
    ];
    let names_none = [
        Outcome::Completed,
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::ClientGone,
        }),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Drain,
        }),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Revoked,
        }),
        Outcome::Aborted(Abort::Superseded {
            by: UnitKey::new(7),
        }),
    ];
    assert!(names_a_step.iter().all(|o| o.step().is_some()));
    assert!(names_none.iter().all(|o| o.step().is_none()));
    assert_eq!(names_a_step[0].step(), Some(StepName::Admit));
}

/// An abort names one reason, and the reason is where it is named.
///
/// `Client`, `Drain` and `Superseded` were spelled twice: once as an `Abort` variant and once as a
/// `ReasonCode`, so the same event could be recorded two ways and a reader could not tell whether
/// the two spellings meant the same thing. The variants that carried nothing the reason does not
/// already carry are gone; the one that carries more than a reason — which unit took over — stays,
/// and answers with its own reason like the rest.
#[test]
fn every_abort_names_a_reason_of_its_own() {
    let aborts = [
        Abort::Kernel {
            reason: ReasonCode::ClientGone,
        },
        Abort::Kernel {
            reason: ReasonCode::Drain,
        },
        Abort::Superseded {
            by: UnitKey::new(7),
        },
    ];
    let reasons: Vec<ReasonCode> = aborts.iter().map(|a| a.reason()).collect();
    assert_eq!(
        reasons,
        vec![
            ReasonCode::ClientGone,
            ReasonCode::Drain,
            ReasonCode::Superseded
        ]
    );

    // Two aborts that answer with one reason would make two endings one row in the record.
    let mut distinct = reasons.clone();
    distinct.sort_unstable_by_key(|r| r.as_str());
    distinct.dedup();
    assert_eq!(distinct.len(), reasons.len(), "two aborts share one reason");

    // The kernel arm passes its reason straight through, so an abort for any reason in the closed
    // vocabulary is recorded as that reason and not as something near it.
    for &code in ReasonCode::ALL {
        assert_eq!(Abort::Kernel { reason: code }.reason(), code);
    }
}

#[test]
fn the_canary_balances_a_clean_run_and_sees_a_missing_settlement() {
    let canary = Canary::new();
    for _ in 0..3 {
        canary.draft_accepted();
        canary.hold_opened();
        canary.settled();
    }
    // A child that accrued into a parent instead of opening its own still has to settle.
    canary.draft_accepted();
    canary.accrual_taken();
    canary.settled();
    assert!(canary.balanced().is_ok());

    // A unit that got through the door and never settled is exactly what this is for.
    canary.draft_accepted();
    canary.hold_opened();
    let broken = canary.balanced().expect_err("one settlement is missing");
    assert_eq!(broken.drafts, 5);
    assert_eq!(broken.holds + broken.accruals, 5);
    assert_eq!(broken.settlements, 4);
}

#[test]
fn the_canary_also_catches_a_settlement_with_no_hold_behind_it() {
    let canary = Canary::new();
    canary.draft_accepted();
    canary.settled();
    assert!(
        canary.balanced().is_err(),
        "a settlement that references no hold is the other side of the same check"
    );
}

#[test]
fn the_lint_hooks_name_every_escape_the_compiler_cannot_close() {
    let symbols: Vec<_> = lint::all().map(|r| r.symbol).collect();
    // The required symbols are data beside the rules (`fixtures/lint_rules.txt`, ruling Q-GG2): a
    // constructor spelled in this file is read by the construction gate as a forged mint. Their
    // count is pinned here, so emptying the list cannot pass this test vacuously.
    let expected = lint::expected();
    assert_eq!(
        expected.len(),
        7,
        "the escapes the scan must keep: {expected:?}"
    );
    assert_eq!(lint::hold_escapes().len(), 6, "the hold-escape list");
    assert_eq!(lint::seal_sites().len(), 3, "the seal-site list");
    for expected in expected {
        assert!(
            symbols.contains(&expected),
            "the source scan must still look for {expected}"
        );
    }
    assert!(lint::all().all(|r| !r.because.is_empty()));

    // A confined rule that names no path would silently allow everything.
    for rule in lint::all() {
        if let lint::LintScope::ConfinedTo(path) = rule.scope {
            assert!(!path.is_empty(), "{} confines to nowhere", rule.symbol);
        }
    }
}

/// The rule list is a specification; the gate is the enforcement. This is the join between them.
///
/// The crate's honesty table says a CI scan looks for these symbols. That claim is only true while
/// the gate's own tables name every one of them: a symbol written down here and absent there is a
/// rule nobody runs, which is exactly the shape of claim this crate exists to refuse to make. The
/// walk is over `lint::all()`, not over one of the two lists — the seal-site rules were the half
/// that no gate rule named, so a test that only read the escape list said nothing about them.
///
/// The scope is checked both ways round. A rule confined to a path that the gate bans outright is
/// a gate that will fail on the one site the rule exists to permit; a rule banned everywhere that
/// the gate confines to a path is a hole the size of that path.
#[test]
fn the_construction_gate_scans_for_every_symbol_this_crate_names() {
    let toml = include_str!("../../../../../qa/construction.toml");

    for rule in lint::all() {
        let named = format!("symbol = {:?}", rule.symbol);
        let (_, after) = toml
            .split_once(&named)
            .unwrap_or_else(|| panic!("qa/construction.toml does not scan for {}", rule.symbol));
        // One symbol's entry is the lines up to the next blank line: its own scope and no other's.
        let entry = after
            .split("\n\n")
            .next()
            .expect("the entry ends somewhere");
        match rule.scope {
            lint::LintScope::ConfinedTo(path) => assert!(
                entry.contains(&format!("confined_to = {path:?}")),
                "{} is confined to {path} here and scoped otherwise in the gate",
                rule.symbol
            ),
            lint::LintScope::BannedEverywhere => assert!(
                entry.contains("confined_to = \"\""),
                "{} is banned everywhere here and confined to somewhere in the gate",
                rule.symbol
            ),
        }
    }

    // A ceiling above zero would let either scan pass with an offending site in the tree.
    for rule_name in ["[rules.hold-escapes]", "[rules.seal-sites]"] {
        let (_, body) = toml
            .split_once(rule_name)
            .unwrap_or_else(|| panic!("the gate carries a {rule_name} rule"));
        assert!(
            body.split("\n[rules.")
                .next()
                .expect("the rule body ends somewhere")
                .contains("max_sites = 0"),
            "{rule_name} does not hold its ceiling at zero"
        );
    }
}

/// One vocabulary, two spellings, and a bridge that cannot be left incomplete.
///
/// The kernel decides in `ReasonCode`; the plane renders `RefusalReason`. While the two sets were
/// written independently, a reason the kernel could raise had no rendering at all, and the ones
/// that did have one were spelled differently on each side — which is how a refusal arrives at a
/// client as some other refusal. The bridge below is the join, and it is exhaustive on purpose:
/// a reason added to the kernel's set does not compile until it has a spelling a client can be
/// shown.
#[test]
fn every_reason_code_has_a_contract_spelling() {
    for &code in ReasonCode::ALL {
        // The conversion is total: a code with no spelling would not compile, and there is no
        // fallback arm for one to hide in.
        let _: crate::unit::RefusalReason = code.into();
    }
}

/// Two codes that render as one spelling make two refusals indistinguishable to whatever reads
/// the record — the same defect the reason set already split `PoolNotPermitted` and `NoRate` out
/// to avoid, so the bridge must not reintroduce it by collapsing them again on the way across.
#[test]
fn the_contract_spelling_of_a_reason_code_is_its_own() {
    use crate::unit::RefusalReason;
    let mut seen: std::collections::HashMap<RefusalReason, ReasonCode> =
        std::collections::HashMap::new();
    for &code in ReasonCode::ALL {
        let reason = RefusalReason::from(code);
        if let Some(previous) = seen.insert(reason, code) {
            panic!("{previous:?} and {code:?} both render as {reason:?}");
        }
    }
    assert_eq!(
        seen.len(),
        ReasonCode::ALL.len(),
        "the bridge collapsed two reasons into one spelling"
    );
}

#[test]
fn a_reason_code_reads_the_same_in_the_journal_and_the_refusal() {
    assert_eq!(ReasonCode::OverBudget.to_string(), "over_budget");
    // Two refusals the ladder answers at different rungs, with different statuses on the wire.
    // They shared a reason with something else until they had their own, which made them
    // indistinguishable to anything reading the record.
    assert_eq!(ReasonCode::PoolNotPermitted.as_str(), "pool_not_permitted");
    assert_eq!(ReasonCode::NoRate.as_str(), "no_rate");
    assert_ne!(ReasonCode::PoolNotPermitted, ReasonCode::ScopeDenied);
    assert_ne!(ReasonCode::NoRate, ReasonCode::Unpriced);
    assert_eq!(StepName::Encode.to_string(), "encode");

    // Two reasons that render the same word would make the journal ambiguous.
    let mut words: Vec<_> = ReasonCode::ALL.iter().map(|r| r.as_str()).collect();
    words.sort_unstable();
    let distinct = words.len();
    words.dedup();
    assert_eq!(words.len(), distinct, "two reasons render the same word");
}
