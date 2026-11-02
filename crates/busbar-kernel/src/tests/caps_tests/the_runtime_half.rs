// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::*;

use crate::canary::Canary;

struct Kernel {
    seal: KernelSeal,
    call_gen: std::sync::atomic::AtomicU64,
}

impl Kernel {
    fn new() -> Self {
        Kernel {
            seal: KernelSeal::acquire_for_kernel(),
            call_gen: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn next_call(&self) -> CallId {
        let gen = self
            .call_gen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        CallId::seal(&self.seal, gen)
    }
    fn admit_token(&self) -> Grant<Admittance> {
        Grant::<Admittance>::mint(&self.seal)
    }

    fn admit_token_for(&self, call: CallId) -> Grant<Admittance> {
        Grant::<Admittance>::mint_bound(&self.seal, call)
    }
    fn exit_token(&self) -> Grant<Exit> {
        Grant::<Exit>::mint(&self.seal)
    }
    fn ledger_token(&self) -> Grant<WriteMoney> {
        Grant::<WriteMoney>::mint(&self.seal)
    }
    fn usage_token(&self) -> Grant<Consumption> {
        Grant::<Consumption>::mint(&self.seal)
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
fn a_refusal_is_stamped_with_the_step_that_raised_it() {
    let k = Kernel::new();
    let token: Pass<Approve> = Pass::mint(&k.seal);
    let decision = SeatVerdict::refuse(
        &token,
        Refusal::new(ReasonCode::ScopeDenied).retry_after(30),
    );

    let refusal = decision
        .into_result(&k.seal)
        .expect_err("this decision refuses");
    assert_eq!(refusal.step(), Some(StepName::Approve));
    assert_eq!(refusal.reason(), ReasonCode::ScopeDenied);
    assert_eq!(refusal.retry_after_secs(), Some(30));
    assert!(!refusal.under_hold(), "approve runs before the door");
}

#[test]
fn a_refusal_that_was_never_stamped_names_no_step() {
    let k = Kernel::new();
    let unstamped = Refusal::new(ReasonCode::OverBudget);
    assert_eq!(unstamped.step(), None);
    assert!(
        !unstamped.under_hold(),
        "a refusal with no step cannot have been raised under a hold"
    );

    let token: Pass<Meter> = Pass::mint(&k.seal);
    let refusal = SeatVerdict::refuse(&token, Refusal::new(ReasonCode::OverBudget))
        .into_result(&k.seal)
        .expect_err("this decision refuses");
    assert_eq!(refusal.step(), Some(StepName::Meter));
    assert!(refusal.under_hold(), "the meter runs after the door");
}

#[test]
fn a_decision_carries_the_facts_of_its_own_step() {
    let k = Kernel::new();
    let token: Pass<Meter> = Pass::mint(&k.seal);
    let decision = SeatVerdict::proceed(&token, usage_of(&k, 42));
    let usage = decision.into_result(&k.seal).expect("this one proceeds");
    assert_eq!(usage.total(), 42);
}

#[test]
fn the_cell_makes_the_one_transition_and_hands_back_the_arrival_hold() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1")));
    assert_eq!(cell.state(), HoldCellState::Arrival);

    let arrival = cell
        .admit(Hold::open(&admit, who("acct-1")), &admit)
        .expect("the first admission wins");
    assert_eq!(cell.state(), HoldCellState::Admitted);
    let _ = Posted::settle(arrival, 0, &usage_of(&k, 0), &k.ledger_token());
}

#[test]
fn two_holds_into_one_cell_fail_and_the_loser_comes_back() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1")));
    let first = cell
        .admit(Hold::open(&admit, who("acct-1")), &admit)
        .expect("first");
    let _ = Posted::settle(first, 0, &usage_of(&k, 0), &k.ledger_token());

    let rejected = cell
        .admit(Hold::open(&admit, who("acct-9")), &admit)
        .expect_err("a cell takes one admission");
    assert_eq!(rejected.error, CellError::AlreadyAdmitted);
    assert_eq!(
        rejected.hold.principal().as_str(),
        "acct-9",
        "the refused hold is handed back, not dropped"
    );
    assert_eq!(
        cell.state(),
        HoldCellState::Admitted,
        "and the cell still holds the first one"
    );
    let _ = Posted::settle(rejected.hold, 0, &usage_of(&k, 0), &k.ledger_token());
}

#[test]
fn the_hold_is_taken_exactly_once_however_many_exits_race() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let exit = k.exit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1")));

    let taken = cell.take(&exit).expect("the first take gets it");
    assert_eq!(cell.state(), HoldCellState::Taken);
    assert!(
        cell.take(&exit).is_none(),
        "the sweep arriving second gets nothing"
    );
    assert!(cell.take(&exit).is_none());

    let rejected = cell
        .admit(Hold::open(&admit, who("acct-1")), &admit)
        .expect_err("a taken cell is final");
    assert_eq!(rejected.error, CellError::AlreadyTaken);
    let _ = Posted::settle(rejected.hold, 0, &usage_of(&k, 0), &k.ledger_token());
    let _ = Posted::settle(taken, 0, &usage_of(&k, 0), &k.ledger_token());
}

#[test]
fn two_threads_racing_the_take_produce_exactly_one_hold() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = std::sync::Arc::new(HoldCell::new(Hold::open(&admit, who("acct-1"))));
    let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let cell = std::sync::Arc::clone(&cell);
        let winners = std::sync::Arc::clone(&winners);
        handles.push(std::thread::spawn(move || {
            let seal = KernelSeal::acquire_for_kernel();
            let exit = Grant::<Exit>::mint(&seal);
            if let Some(hold) = cell.take(&exit) {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let ledger = Grant::<WriteMoney>::mint(&seal);
                let usage = Grant::<Consumption>::mint(&seal);
                let usage = Usage::report(&usage, Vec::new()).expect("empty is fine");
                let _ = Posted::settle(hold, 0, &usage, &ledger);
            }
        }));
    }
    for h in handles {
        h.join().expect("no thread panics");
    }
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn a_child_posting_racing_the_sweep_answers_under_one_guard() {
    use std::sync::atomic::{AtomicBool, Ordering as Order};

    fn jitter(n: usize) {
        for _ in 0..n {
            std::hint::spin_loop();
        }
    }

    let mut clean = 0usize;
    let mut late = 0usize;
    for round in 0..10_000usize {
        let k = Kernel::new();
        let admit = k.admit_token();
        let cell = std::sync::Arc::new(HoldCell::new(Hold::open(&admit, who("acct-1"))));
        let arrival = cell
            .admit(Hold::open(&admit, who("acct-1")), &admit)
            .expect("the parent passes the door");
        let _ = Posted::settle(arrival, 0, &usage_of(&k, 0), &k.ledger_token());
        let accrual = cell
            .accrue_child(&who("acct-1"), &admit)
            .expect("an open parent takes the child");

        let swept = std::sync::Arc::new(AtomicBool::new(false));
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let sweep_cell = std::sync::Arc::clone(&cell);
        let sweep_flag = std::sync::Arc::clone(&swept);
        let sweep_start = std::sync::Arc::clone(&start);
        let sweep = std::thread::spawn(move || {
            let seal = KernelSeal::acquire_for_kernel();
            let exit = Grant::<Exit>::mint(&seal);
            sweep_start.wait();
            jitter((round % 64) * 64);
            let taken = sweep_cell.take(&exit);
            sweep_flag.store(true, Order::SeqCst);
            if let Some(hold) = taken {
                let usage = Usage::report(&Grant::<Consumption>::mint(&seal), Vec::new())
                    .expect("empty is fine");
                let _ = Posted::settle(hold, 0, &usage, &Grant::<WriteMoney>::mint(&seal));
            }
        });

        let ledger = k.ledger_token();
        start.wait();
        jitter((63 - round % 64) * 64);
        let parent_already_gone = swept.load(Order::SeqCst);
        let posted = match cell.post_child(accrual, &ledger) {
            Ok(posted) => posted,
            Err(missed) => Posted::settle_late(missed, &ledger),
        };
        sweep.join().expect("no thread panics");

        assert_eq!(
            posted.principal().as_str(),
            "acct-1",
            "the child posts for its own principal whichever way the race fell"
        );
        if posted.flags().is_clean() {
            assert!(
                !parent_already_gone,
                "a clean in-parent posting against a slot the sweep had already emptied"
            );
            clean += 1;
        } else {
            assert_eq!(
                posted.flags(),
                PostingFlags::LATE_ACCRUAL,
                "the only other answer is the late one"
            );
            late += 1;
        }
    }
    assert_eq!(clean + late, 10_000, "every iteration posts exactly once");
    assert!(
        clean > 0 && late > 0,
        "the slot was never actually contended: {clean} clean, {late} late"
    );
}

#[test]
fn an_accrual_is_sealed_to_an_admitted_parent_with_the_same_principal() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let cell = HoldCell::new(Hold::open(&admit, who("acct-1")));

    assert_eq!(
        cell.accrue_child(&who("acct-1"), &admit).unwrap_err(),
        AccrualRefused::ParentNotAdmitted
    );

    let arrival = cell
        .admit(Hold::open(&admit, who("acct-1")), &admit)
        .expect("admitted");
    let _ = Posted::settle(arrival, 0, &usage_of(&k, 0), &k.ledger_token());

    assert_eq!(
        cell.accrue_child(&who("acct-2"), &admit).unwrap_err(),
        AccrualRefused::PrincipalMismatch
    );

    let accrual = cell
        .accrue_child(&who("acct-1"), &admit)
        .expect("same principal, parent admitted");
    assert_eq!(accrual.principal().as_str(), "acct-1");
    assert_eq!(cell.accruals(), 1);

    let parent = cell.take(&k.exit_token()).expect("the parent exits");
    assert_eq!(
        cell.accrue_child(&who("acct-1"), &admit).unwrap_err(),
        AccrualRefused::ParentExited
    );

    let posted = Posted::settle_late(accrual, &k.ledger_token());
    assert!(posted.flags().contains(PostingFlags::LATE_ACCRUAL));
    assert_eq!(posted.principal().as_str(), "acct-1");
    let _ = Posted::settle(parent, 10, &usage_of(&k, 10), &k.ledger_token());
}

#[test]
fn an_estimated_usage_report_flags_the_posting() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let hold = Hold::open(&admit, who("acct-1"));
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

    let posted = Posted::settle(hold, 100, &floor, &k.ledger_token());
    assert!(posted.flags().contains(PostingFlags::ESTIMATED));
    assert!(!posted.flags().is_clean());
}

#[test]
fn a_usage_report_is_bounded_by_the_record_size() {
    let k = Kernel::new();

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

    let hold = Hold::open(&admit, who("acct-1"));
    let posted = Posted::settle(hold, 10, &usage_of(&k, 10), &k.ledger_token());
    let end = UnitEnd::seal(&exit, Outcome::Completed, Ok(posted));
    assert!(end.outcome().is_completed());
    assert_eq!(end.posted().map(Posted::quantity), Ok(10));

    let lost = DurabilityLost::observed(&Grant::<DurableWrite>::mint(&k.seal), StepName::Meter);
    let end = UnitEnd::seal(
        &exit,
        Outcome::Failed(StepName::Meter, ReasonCode::DurabilityUnavailable),
        Err(lost),
    );
    assert_eq!(end.outcome().step(), Some(StepName::Meter));
    assert_eq!(end.into_posted().unwrap_err().step(), StepName::Meter);
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
    let handle = TransportKeyHandle::issue(&Grant::<KeyHandle>::mint(&k.seal), 11, "sha256:ab");
    assert_eq!(
        format!("{handle:?}"),
        "TransportKeyHandle(slot 11, sha256:ab <no material>)"
    );
}

#[test]
fn a_sealed_destination_carries_the_lane_the_money_side_reads() {
    let k = Kernel::new();
    let dest = VerifiedDestination::seal(
        &Grant::<Dial>::mint(&k.seal),
        LaneId::new("vendor-a:gpt-4o"),
    );
    assert_eq!(dest.lane().as_str(), "vendor-a:gpt-4o");
}

#[test]
fn every_origin_spells_itself_the_way_the_journal_reads_it() {
    let k = Kernel::new();
    let table = [
        (OriginKind::Client, "client"),
        (OriginKind::Provider, "provider"),
        (OriginKind::Tick, "tick"),
        (OriginKind::Arrival, "arrival"),
        (OriginKind::Handshake, "handshake"),
        (OriginKind::Bootstrap, "bootstrap"),
        (
            OriginKind::Nested {
                parent: UnitKey::new(1),
            },
            "nested",
        ),
        (
            OriginKind::Delivery {
                parent: UnitKey::new(2),
            },
            "delivery",
        ),
    ];
    assert_eq!(table.len(), 8, "eight places a unit can come from");
    for (kind, spelling) in table {
        assert_eq!(kind.as_str(), spelling);

        assert_eq!(Origin::seal(&k.seal, kind).as_str(), spelling);
        assert_eq!(Origin::seal(&k.seal, kind).kind(), kind);
    }
}

#[test]
fn a_token_says_which_step_it_is_for() {
    let k = Kernel::new();
    let token: Pass<Verify> = Pass::mint(&k.seal);
    assert_eq!(format!("{token:?}"), "Pass<verify>");
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k.seal);
    assert_eq!(format!("{admit:?}"), "Grant<admittance>");
    assert_eq!(format!("{:?}", Grant::<Dial>::mint(&k.seal)), "Grant<dial>");
}

#[test]
fn the_doors_answer_is_one_of_three_shapes() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let token: Pass<Admit> = Pass::mint(&k.seal);

    let decision = SeatVerdict::proceed(&token, Admission::Own(Hold::open(&admit, who("acct-1"))));
    match decision.into_result(&k.seal).expect("proceeds") {
        Admission::Own(hold) => {
            let _ = Posted::settle(hold, 5, &usage_of(&k, 5), &k.ledger_token());
        }
        other => panic!("expected the unit's own hold, got {other:?}"),
    }

    let token: Pass<Admit> = Pass::mint(&k.seal);
    let decision = SeatVerdict::proceed(&token, Admission::ZeroHold);
    assert!(matches!(
        decision.into_result(&k.seal).expect("proceeds"),
        Admission::ZeroHold
    ));
}

#[test]
fn a_child_posts_inside_its_parent_while_the_parent_is_open() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let parent = HoldCell::new(Hold::open(&admit, who("acct-1")));
    let arrival = parent
        .admit(Hold::open(&admit, who("acct-1")), &admit)
        .expect("the parent passes the door");
    let _ = Posted::settle(arrival, 0, &usage_of(&k, 0), &k.ledger_token());

    let accrual = parent
        .accrue_child(&who("acct-1"), &admit)
        .expect("an open parent takes the child");

    let posted =
        Posted::into_parent(accrual, &parent, &k.ledger_token()).expect("the parent is still open");
    assert_eq!(posted.principal().as_str(), "acct-1");
    assert!(
        posted.flags().is_clean(),
        "nothing about a child that met its parent is late"
    );
}

#[test]
fn a_child_whose_parent_exited_gets_its_accrual_back_and_posts_late() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let parent = HoldCell::new(Hold::open(&admit, who("acct-1")));
    let arrival = parent
        .admit(Hold::open(&admit, who("acct-1")), &admit)
        .expect("the parent passes the door");
    let _ = Posted::settle(arrival, 0, &usage_of(&k, 0), &k.ledger_token());
    let accrual = parent
        .accrue_child(&who("acct-1"), &admit)
        .expect("an open parent takes the child");

    let taken = parent.take(&k.exit_token()).expect("the parent's own exit");
    let _ = Posted::settle(taken, 0, &usage_of(&k, 0), &k.ledger_token());

    let handed_back = Posted::into_parent(accrual, &parent, &k.ledger_token())
        .expect_err("a parent that has gone cannot carry it");
    assert_eq!(handed_back.principal().as_str(), "acct-1");

    let late = Posted::settle_late(handed_back, &k.ledger_token());
    assert!(late.flags().contains(PostingFlags::LATE_ACCRUAL));
    assert_eq!(late.principal().as_str(), "acct-1");
}

#[test]
fn an_outstanding_accrual_becomes_a_hold_of_its_own_at_the_parents_exit() {
    let k = Kernel::new();
    let admit = k.admit_token();
    let parent = HoldCell::new(Hold::open(&admit, who("acct-1")));
    let arrival = parent
        .admit(Hold::open(&admit, who("acct-1")), &admit)
        .expect("the parent passes the door");
    let _ = Posted::settle(arrival, 0, &usage_of(&k, 0), &k.ledger_token());
    let accrual = parent
        .accrue_child(&who("acct-1"), &admit)
        .expect("an open parent takes the child");

    let converted = accrual
        .convert_at_parent_exit(&admit)
        .expect("the accruing call's own grant converts it");
    assert_eq!(converted.principal(), &who("acct-1"));
    let posted = Posted::settle(converted, 250, &usage_of(&k, 250), &k.ledger_token());
    assert_eq!(posted.quantity(), 250);
    assert!(
        !posted.flags().contains(PostingFlags::LATE_ACCRUAL),
        "a converted accrual is not a late one: it has its own hold"
    );
}

#[test]
fn a_grant_of_another_call_neither_admits_nor_converts() {
    let k = Kernel::new();
    let (call_a, call_b) = (k.next_call(), k.next_call());
    let (grant_a, grant_b) = (k.admit_token_for(call_a), k.admit_token_for(call_b));

    let cell = HoldCell::new(Hold::open(&grant_b, who("acct-1")));
    let rejected = cell
        .admit(Hold::open(&grant_b, who("acct-9")), &grant_a)
        .expect_err("call A's grant admitted call B's hold");
    assert_eq!(rejected.error, CellError::CallMismatch);
    assert_eq!(
        rejected.hold.principal().as_str(),
        "acct-9",
        "the refused hold did not come back whole"
    );
    let arrival = cell
        .admit(rejected.hold, &grant_b)
        .expect("call B's own grant admits its hold");
    let _ = Posted::settle(arrival, 0, &usage_of(&k, 0), &k.ledger_token());

    let accrual = cell
        .accrue_child(&who("acct-9"), &grant_b)
        .expect("an open parent takes the child");
    let accrual = accrual
        .convert_at_parent_exit(&grant_a)
        .expect_err("call A's grant converted call B's accrual");
    let converted = accrual
        .convert_at_parent_exit(&grant_b)
        .expect("call B's own grant converts it");
    assert_eq!(converted.call(), call_b);
    let _ = Posted::settle(converted, 250, &usage_of(&k, 250), &k.ledger_token());
}

#[test]
fn the_canary_balances_a_clean_run_and_sees_a_missing_settlement() {
    let canary = Canary::new();
    for _ in 0..3 {
        canary.draft_accepted();
        canary.hold_opened();
        canary.settled();
    }

    canary.draft_accepted();
    canary.accrual_taken();
    canary.settled();
    assert!(canary.balanced().is_ok());

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
