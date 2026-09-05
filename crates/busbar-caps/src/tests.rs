// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The runtime half of the proof. The compile-time half is the compile-fail fixtures in the module
//! documentation; what is left over is what only a running program can show: that the cell is a
//! state machine, that a hold is taken once, that an accrual is sealed to its parent, and that the
//! canary sees a unit that goes missing.

use crate::*;

/// The lint rule data. It is a proof, not surface: no plugin, unit or kernel path names it, so it
/// lives beside the crate rather than inside it and is pulled in here for the test that keeps it
/// from going empty or stale.
mod lint {
    include!("../fixtures/lint_rules.rs");
}

/// Everything a test needs to act as the kernel, in one place, so no test quietly reaches for the
/// seal on its own.
struct Kernel {
    seal: KernelSeal,
}

impl Kernel {
    fn new() -> Self {
        Kernel {
            seal: KernelSeal::acquire_for_kernel(),
        }
    }
    fn admit_token(&self) -> AdmitToken<Admit> {
        AdmitToken::mint(&self.seal)
    }
    fn exit_token(&self) -> ExitToken {
        ExitToken::mint(&self.seal)
    }
    fn ledger_token(&self) -> LedgerToken {
        LedgerToken::mint(&self.seal)
    }
    fn usage_token(&self) -> UsageToken {
        UsageToken::mint(&self.seal)
    }
}

fn who(id: &str) -> PrincipalId {
    PrincipalId::new(id)
}

fn usage_of(k: &Kernel, quantity: u64) -> Usage {
    Usage::report(
        &k.usage_token(),
        vec![UsageLine {
            class: MeterClassId::new("tokens"),
            quantity,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line is within the bound")
}

#[test]
fn the_ten_steps_are_in_order_and_three_belong_to_the_kernel() {
    assert_eq!(StepName::ALL.len(), 10);
    let mut sorted = StepName::ALL;
    sorted.sort();
    assert_eq!(sorted, StepName::ALL, "the list is already in loop order");

    let kernel_owned: Vec<_> = StepName::ALL
        .iter()
        .filter(|s| s.kernel_owned())
        .copied()
        .collect();
    assert_eq!(
        kernel_owned,
        vec![StepName::Arrival, StepName::Decode, StepName::Encode]
    );

    // The marker's constant and the runtime name agree, for every step.
    assert_eq!(<Admit as Step>::NAME, StepName::Admit);
    // The marker's constant and the runtime name agree about who owns the token, for both kinds.
    assert_eq!(
        <Admit as Step>::KERNEL_OWNED,
        <Admit as Step>::NAME.kernel_owned()
    );
    assert_eq!(
        <Encode as Step>::KERNEL_OWNED,
        <Encode as Step>::NAME.kernel_owned()
    );

    // Under-hold is a comparison, and it starts strictly after the door.
    assert!(!StepName::Admit.under_hold());
    assert!(StepName::Route.under_hold());
    assert!(StepName::Audit.under_hold());
}

#[test]
fn a_refusal_is_stamped_with_the_step_that_raised_it() {
    let k = Kernel::new();
    let token: UnitToken<Approve> = UnitToken::mint(&k.seal);
    let decision = Decision::refuse(
        &token,
        Refusal::new(ReasonCode::ScopeDenied).retry_after(30),
    );

    let refusal = decision
        .into_result(&k.seal)
        .expect_err("this decision refuses");
    assert_eq!(refusal.step(), StepName::Approve);
    assert_eq!(refusal.reason(), ReasonCode::ScopeDenied);
    assert_eq!(refusal.retry_after_secs(), Some(30));
    assert!(!refusal.under_hold(), "approve runs before the door");
}

#[test]
fn a_decision_carries_the_facts_of_its_own_step() {
    let k = Kernel::new();
    let token: UnitToken<Meter> = UnitToken::mint(&k.seal);
    let decision = Decision::proceed(&token, usage_of(&k, 42));
    let usage = decision.into_result(&k.seal).expect("this one proceeds");
    assert_eq!(usage.total(), 42);
}

#[test]
fn the_cell_makes_the_one_transition_and_hands_back_the_arrival_hold() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1"), 0));
    assert_eq!(cell.state(), HoldCellState::Arrival);

    let arrival = cell
        .admit(Hold::open(&admit, who("acct-1"), 1_000), &admit)
        .expect("the first admission wins");
    assert_eq!(arrival.reserved(), 0, "the arrival hold reserved nothing");
    assert_eq!(cell.state(), HoldCellState::Admitted);
    let _ = Posted::settle(arrival, &usage_of(&k, 0), &k.ledger_token());
}

#[test]
fn two_holds_into_one_cell_fail_and_the_loser_comes_back() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1"), 0));
    let first = cell
        .admit(Hold::open(&admit, who("acct-1"), 1_000), &admit)
        .expect("first");
    let _ = Posted::settle(first, &usage_of(&k, 0), &k.ledger_token());

    let rejected = cell
        .admit(Hold::open(&admit, who("acct-1"), 9_999), &admit)
        .expect_err("a cell takes one admission");
    assert_eq!(rejected.error, CellError::AlreadyAdmitted);
    assert_eq!(
        rejected.hold.reserved(),
        9_999,
        "the refused hold is handed back, not dropped"
    );
    assert_eq!(
        cell.state(),
        HoldCellState::Admitted,
        "and the cell still holds the first one"
    );
    let _ = Posted::settle(rejected.hold, &usage_of(&k, 0), &k.ledger_token());
}

#[test]
fn the_hold_is_taken_exactly_once_however_many_exits_race() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let exit = k.exit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1"), 500));

    let taken = cell.take(&exit).expect("the first take gets it");
    assert_eq!(cell.state(), HoldCellState::Taken);
    assert!(
        cell.take(&exit).is_none(),
        "the sweep arriving second gets nothing"
    );
    assert!(cell.take(&exit).is_none());

    // And nothing can put one back afterwards.
    let rejected = cell
        .admit(Hold::open(&admit, who("acct-1"), 1), &admit)
        .expect_err("a taken cell is final");
    assert_eq!(rejected.error, CellError::AlreadyTaken);
    let _ = Posted::settle(rejected.hold, &usage_of(&k, 0), &k.ledger_token());
    let _ = Posted::settle(taken, &usage_of(&k, 0), &k.ledger_token());
}

#[test]
fn two_threads_racing_the_take_produce_exactly_one_hold() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = std::sync::Arc::new(HoldCell::new(Hold::open(&admit, who("acct-1"), 7)));
    let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let cell = std::sync::Arc::clone(&cell);
        let winners = std::sync::Arc::clone(&winners);
        handles.push(std::thread::spawn(move || {
            // Each thread is its own exit-path caller; only one can win.
            let seal = KernelSeal::acquire_for_kernel();
            let exit = ExitToken::mint(&seal);
            if let Some(hold) = cell.take(&exit) {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let ledger = LedgerToken::mint(&seal);
                let usage = UsageToken::mint(&seal);
                let usage = Usage::report(&usage, Vec::new()).expect("empty is fine");
                let _ = Posted::settle(hold, &usage, &ledger);
            }
        }));
    }
    for h in handles {
        h.join().expect("no thread panics");
    }
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn a_hold_accrues_until_the_reservation_runs_out_then_tops_up() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let mut hold = Hold::open(&admit, who("acct-1"), 100);

    assert_eq!(hold.accrue(60), Accrual::Within { remaining: 40 });
    assert_eq!(hold.accrue(30), Accrual::Within { remaining: 10 });
    assert_eq!(hold.accrue(25), Accrual::Exhausted { shortfall: 15 });

    // One top-up from the slice covers the shortfall and the hold carries on.
    assert_eq!(hold.top_up(50), 35);
    assert_eq!(hold.accrued(), 115);
    assert_eq!(hold.reserved(), 150);

    // The slice is empty and the reserve is refused: the unit still finishes and posts the lot.
    assert_eq!(hold.accrue(40), Accrual::Exhausted { shortfall: 5 });
    hold.record_overdraft(5);
    assert_eq!(hold.overdraft(), 5);

    let posted = Posted::settle(hold, &usage_of(&k, 155), &k.ledger_token());
    assert_eq!(posted.settled(), 155);
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
    assert!(!posted.flags().contains(PostingFlags::RECOVERED));
}

#[test]
fn an_accrual_is_sealed_to_an_admitted_parent_with_the_same_principal() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1"), 0));

    // Before the door: nothing to accrue into.
    assert_eq!(
        cell.accrue_child(&who("acct-1"), 10, &admit).unwrap_err(),
        AccrualRefused::ParentNotAdmitted
    );

    let arrival = cell
        .admit(Hold::open(&admit, who("acct-1"), 1_000), &admit)
        .expect("admitted");
    let _ = Posted::settle(arrival, &usage_of(&k, 0), &k.ledger_token());

    // A stranger's child cannot spend this admission.
    assert_eq!(
        cell.accrue_child(&who("acct-2"), 10, &admit).unwrap_err(),
        AccrualRefused::PrincipalMismatch
    );

    let accrual = cell
        .accrue_child(&who("acct-1"), 10, &admit)
        .expect("same principal, parent admitted");
    assert_eq!(accrual.amount(), 10);
    assert_eq!(cell.accruals(), 1);

    // After the parent exits, a late child is refused and posts on its own instead.
    let parent = cell.take(&k.exit_token()).expect("the parent exits");
    assert_eq!(
        parent.accrued(),
        10,
        "the child's spend landed on the parent"
    );
    assert_eq!(
        cell.accrue_child(&who("acct-1"), 10, &admit).unwrap_err(),
        AccrualRefused::ParentExited
    );

    let late = HoldCell::new(Hold::open(&admit, who("acct-1"), 0));
    let _ = late.take(&k.exit_token());
    let posted = Posted::settle_late(accrual, &k.ledger_token());
    assert!(posted.flags().contains(PostingFlags::LATE_ACCRUAL));
    assert_eq!(posted.settled(), 10);
    let _ = Posted::settle(parent, &usage_of(&k, 10), &k.ledger_token());
}

#[test]
fn a_recovered_hold_says_so_all_the_way_onto_the_posting() {
    let k = Kernel::new();
    let recovery = RecoveryToken::mint(&k.seal);
    let hold = Hold::materialize(&recovery, who("acct-1"), 1_000, 250);
    assert!(hold.is_recovered());
    assert_eq!(hold.accrued(), 250, "the last checkpointed accrual");

    let posted = Posted::settle(hold, &usage_of(&k, 250), &k.ledger_token());
    assert!(posted.flags().contains(PostingFlags::RECOVERED));
}

#[test]
fn an_estimated_usage_report_flags_the_posting() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let hold = Hold::open(&admit, who("acct-1"), 100);
    let floor = Usage::estimate(
        &k.usage_token(),
        vec![UsageLine {
            class: MeterClassId::new("tokens"),
            quantity: 100,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("within the bound");
    assert!(floor.is_estimated());

    let posted = Posted::settle(hold, &floor, &k.ledger_token());
    assert!(posted.flags().contains(PostingFlags::ESTIMATED));
    assert!(!posted.flags().is_clean());
}

#[test]
fn a_usage_report_is_bounded_by_the_record_size() {
    let k = Kernel::new();
    // A meter class is a declared name, so the over-long report is built from declared names; the
    // ceiling is on the line count, not on the class, so one repeated class proves it just as well.
    let lines: Vec<_> = (0..MAX_USAGE_LINES + 1)
        .map(|_| UsageLine {
            class: MeterClassId::new("class"),
            quantity: 1,
            source: QuantitySource::Count,
            estimated: false,
        })
        .collect();
    assert_eq!(
        Usage::report(&k.usage_token(), lines).unwrap_err(),
        UsageError::TooManyLines
    );
}

#[test]
fn a_unit_end_carries_its_posting_or_the_loss_that_replaced_it() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let exit = k.exit_token();

    let hold = Hold::open(&admit, who("acct-1"), 10);
    let posted = Posted::settle(hold, &usage_of(&k, 10), &k.ledger_token());
    let end = UnitEnd::seal(&exit, Outcome::Completed, Ok(posted));
    assert!(end.outcome().is_completed());
    assert_eq!(end.posted().map(Posted::settled), Ok(10));

    let lost = DurabilityLost::observed(&DurabilityToken::mint(&k.seal), StepName::Meter);
    let end = UnitEnd::seal(
        &exit,
        Outcome::Failed(StepName::Meter, ReasonCode::DurabilityUnavailable),
        Err(lost),
    );
    assert_eq!(end.outcome().step(), Some(StepName::Meter));
    assert_eq!(end.into_posted().unwrap_err().step(), StepName::Meter);
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
        Outcome::Aborted(Abort::Client),
        Outcome::Aborted(Abort::Drain),
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

#[test]
fn the_kernels_own_types_are_sealed_and_readable() {
    let k = Kernel::new();
    let origin = Origin::seal(
        &k.seal,
        OriginKind::Nested {
            parent: UnitKey::new(3),
        },
    );
    assert_eq!(origin.as_str(), "nested");
    assert_eq!(
        origin.kind(),
        OriginKind::Nested {
            parent: UnitKey::new(3)
        }
    );
    assert_eq!(SessionId::mint(&k.seal, 9).get(), 9);
    assert_eq!(IdempotencyKey::mint(&k.seal, [7; 32]).bytes()[0], 7);
}

#[test]
fn the_egress_capabilities_never_print_what_they_carry() {
    let k = Kernel::new();
    let handle = TransportKeyHandle::issue(&TransportKeyToken::mint(&k.seal), 11, "sha256:ab");
    assert_eq!(
        format!("{handle:?}"),
        "TransportKeyHandle(slot 11, sha256:ab <no material>)"
    );

    let once = SecretOnce::mint(
        &AdminToken::mint(&k.seal),
        0xdead_beef_dead_beef_dead_beef_dead_beef,
        UnitKey::new(1),
        "/body/secret",
    );
    let printed = format!("{once:?}");
    assert!(printed.contains("/body/secret"));
    assert!(
        !printed.contains("dead"),
        "the nonce is never printed: {printed}"
    );
    assert!(once.matches(0xdead_beef_dead_beef_dead_beef_dead_beef));
    assert!(!once.matches(1));
}

#[test]
fn a_sealed_destination_carries_the_lane_the_money_side_reads() {
    let k = Kernel::new();
    let dest = VerifiedDestination::seal(&TrustToken::mint(&k.seal), LaneId::new("openai:gpt-4o"));
    assert_eq!(dest.lane().as_str(), "openai:gpt-4o");

    let decoration = AuthDecoration::decorate(
        &EgressAuthToken::mint(&k.seal),
        vec![("authorization".into(), "Bearer {slot}".into())],
        true,
        vec![SecretSlot::declare(
            &EgressAuthToken::mint(&k.seal),
            "header:authorization",
        )],
    );
    match decoration {
        AuthDecoration::Decorate { slots, .. } => {
            assert_eq!(slots[0].location(), "header:authorization")
        }
        AuthDecoration::Handshake { .. } => panic!("built a decoration, got a handshake"),
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
    for expected in [
        "mem::forget",
        "ManuallyDrop",
        "Box::leak",
        "AssertUnwindSafe",
        "KernelSeal::acquire_for_kernel",
        "RecoveryToken",
        "HoldCell::take",
    ] {
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

#[test]
fn a_reason_code_reads_the_same_in_the_journal_and_the_refusal() {
    assert_eq!(ReasonCode::OverBudget.to_string(), "over_budget");
    assert_eq!(StepName::Encode.to_string(), "encode");

    // Two reasons that render the same word would make the journal ambiguous.
    let mut words: Vec<_> = ReasonCode::ALL.iter().map(|r| r.as_str()).collect();
    words.sort_unstable();
    let distinct = words.len();
    words.dedup();
    assert_eq!(words.len(), distinct, "two reasons render the same word");
}

#[test]
fn a_token_says_which_step_it_is_for() {
    let k = Kernel::new();
    let token: UnitToken<Verify> = UnitToken::mint(&k.seal);
    assert_eq!(format!("{token:?}"), "UnitToken<verify>");
    let admit: AdmitToken<Admit> = AdmitToken::mint(&k.seal);
    assert_eq!(format!("{admit:?}"), "AdmitToken<admit>");
    assert_eq!(format!("{:?}", TrustToken::mint(&k.seal)), "TrustToken");
}

#[test]
fn the_doors_answer_is_one_of_three_shapes() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let token: UnitToken<Admit> = UnitToken::mint(&k.seal);

    let decision = Decision::proceed(&token, Admission::Own(Hold::open(&admit, who("acct-1"), 5)));
    match decision.into_result(&k.seal).expect("proceeds") {
        Admission::Own(hold) => {
            let _ = Posted::settle(hold, &usage_of(&k, 5), &k.ledger_token());
        }
        other => panic!("expected the unit's own hold, got {other:?}"),
    }

    // A zero-priced unit holds nothing, which is why the heartbeat always runs.
    let token: UnitToken<Admit> = UnitToken::mint(&k.seal);
    let decision = Decision::proceed(&token, Admission::ZeroHold);
    assert!(matches!(
        decision.into_result(&k.seal).expect("proceeds"),
        Admission::ZeroHold
    ));
}
