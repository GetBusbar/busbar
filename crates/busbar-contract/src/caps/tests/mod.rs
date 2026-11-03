// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The runtime half of the proof that needs no token. The compile-time half is the compile-fail

use crate::caps::*;

#[cfg(feature = "test-seal")]
#[test]
fn child_preparation_cannot_leave_an_accrual_on_failure_or_an_invalid_parent() {
    let seal = KernelSeal::acquire_for_kernel();
    let call = CallId::seal(&seal, 51);
    let admit = Grant::<Admittance>::mint_bound(&seal, call);
    let principal = PrincipalId::new("parent");
    let cell = HoldCell::new(Hold::open(&admit, principal.clone()));
    let not_called = || -> Result<(), &'static str> { panic!("invalid parent prepared") };
    assert_eq!(
        cell.accrue_child_after(&principal, &admit, not_called)
            .unwrap_err(),
        AccrualPrepareError::Parent(AccrualRefused::ParentNotAdmitted)
    );
    let arrival = cell
        .admit(Hold::open(&admit, principal.clone()), &admit)
        .unwrap();
    assert_eq!(
        cell.accrue_child_after(&PrincipalId::new("other"), &admit, not_called)
            .unwrap_err(),
        AccrualPrepareError::Parent(AccrualRefused::PrincipalMismatch)
    );
    assert_eq!(
        cell.accrue_child_after(&principal, &admit, || Err("registration refused"))
            .unwrap_err(),
        AccrualPrepareError::Prepare("registration refused")
    );
    assert_eq!(cell.state(), HoldCellState::Admitted);
    assert_eq!(cell.accruals(), 0);
    let calls = std::cell::Cell::new(0);
    let child = Grant::<Admittance>::mint_bound(&seal, CallId::seal(&seal, 52));
    let accrual = cell
        .accrue_child_after(&principal, &child, || {
            calls.set(calls.get() + 1);
            Ok::<(), &'static str>(())
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(cell.accruals(), 1);
    let admitted = cell.take(&Grant::<Exit>::mint_bound(&seal, call)).unwrap();
    assert_eq!(
        cell.accrue_child_after(&principal, &child, not_called)
            .unwrap_err(),
        AccrualPrepareError::Parent(AccrualRefused::ParentExited)
    );
    assert_eq!(cell.accruals(), 1);
    let posted = Posted::settle_late(
        accrual,
        &Grant::<WriteMoney>::mint_bound(&seal, child.call()),
    );
    drop((arrival, admitted, posted));
}

#[cfg(feature = "test-seal")]
#[test]
fn admitted_cell_authority_requires_its_call_principal_and_live_admission() {
    let seal = KernelSeal::acquire_for_kernel();
    let call = CallId::seal(&seal, 41);
    let admit = Grant::<Admittance>::mint_bound(&seal, call);
    let other = Grant::<Admittance>::mint_bound(&seal, CallId::seal(&seal, 42));
    let principal = PrincipalId::new("caller");
    let stranger = PrincipalId::new("stranger");
    let cell = HoldCell::new(Hold::open(&admit, principal.clone()));
    assert!(!cell.admitted_for(&admit, &principal));
    assert_eq!(cell.state(), HoldCellState::Arrival);
    let arrival = cell
        .admit(Hold::open(&admit, principal.clone()), &admit)
        .unwrap();
    assert!(cell.admitted_for(&admit, &principal));
    assert!(!cell.admitted_for(&other, &principal));
    assert!(!cell.admitted_for(&admit, &stranger));
    assert_eq!(cell.state(), HoldCellState::Admitted);
    assert_eq!(cell.accruals(), 0);
    let exit = Grant::<Exit>::mint_bound(&seal, call);
    let admitted = cell.take(&exit).unwrap();
    assert!(!cell.admitted_for(&admit, &principal));
    assert_eq!(cell.state(), HoldCellState::Taken);
    drop((arrival, admitted));
}

/// The lint rule data. It is a proof, not surface: no plugin, unit or kernel path names it, so it
mod lint {
    include!("../fixtures/lint_rules.rs");
}

/// The renderings every one of these types hand-rolls, read back — including the two that carry
mod what_the_record_reads;

/// The posting's flags: distinct bits, every one the type declares.
mod the_posting_arithmetic;

/// Where a reported quantity came from, and the three questions the crate asks about it.
mod what_the_usage_report_says;

/// Whether the kernel keeps this step's token to itself, read off the step markers' own
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

    let kernel_owned: Vec<_> = StepName::ALL
        .iter()
        .filter(|s| kernel_owned_marker(**s))
        .copied()
        .collect();
    assert_eq!(
        kernel_owned,
        vec![StepName::Arrival, StepName::Decode, StepName::Encode]
    );

    assert_eq!(<Admit as Step>::NAME, StepName::Admit);

    assert!(!StepName::Admit.under_hold());
    assert!(StepName::Route.under_hold());
    assert!(StepName::Audit.under_hold());
}

#[test]
fn every_way_a_unit_can_end_names_a_step_or_deliberately_does_not() {
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

    let mut distinct = reasons.clone();
    distinct.sort_unstable_by_key(|r| r.as_str());
    distinct.dedup();
    assert_eq!(distinct.len(), reasons.len(), "two aborts share one reason");

    for &code in ReasonCode::ALL {
        assert_eq!(Abort::Kernel { reason: code }.reason(), code);
    }
}

#[test]
fn the_lint_hooks_name_every_escape_the_compiler_cannot_close() {
    let symbols: Vec<_> = lint::all().map(|r| r.symbol).collect();

    let expected = lint::expected();
    assert_eq!(
        expected.len(),
        9,
        "the escapes the scan must keep: {expected:?}"
    );
    assert_eq!(lint::hold_escapes().len(), 9, "the hold-escape list");
    assert_eq!(lint::seal_sites().len(), 2, "the seal-site list");
    for expected in expected {
        assert!(
            symbols.contains(&expected),
            "the source scan must still look for {expected}"
        );
    }
    assert!(lint::all().all(|r| !r.because.is_empty()));

    for rule in lint::all() {
        if let lint::LintScope::ConfinedTo(path) = rule.scope {
            assert!(!path.is_empty(), "{} confines to nowhere", rule.symbol);
        }
    }
}

/// One vocabulary, two spellings, and a bridge that cannot be left incomplete.
#[test]
fn every_reason_code_has_a_contract_spelling() {
    for &code in ReasonCode::ALL {
        let _: crate::unit::RefusalReason = code.into();
    }
}

/// Two codes that render as one spelling make two refusals indistinguishable to whatever reads
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

    assert_eq!(ReasonCode::PoolNotPermitted.as_str(), "pool_not_permitted");
    assert_eq!(ReasonCode::NoRate.as_str(), "no_rate");
    assert_ne!(ReasonCode::PoolNotPermitted, ReasonCode::ScopeDenied);
    assert_ne!(ReasonCode::NoRate, ReasonCode::Unpriced);
    assert_eq!(StepName::Encode.to_string(), "encode");

    let mut words: Vec<_> = ReasonCode::ALL.iter().map(|r| r.as_str()).collect();
    words.sort_unstable();
    let distinct = words.len();
    words.dedup();
    assert_eq!(words.len(), distinct, "two reasons render the same word");
}
