// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hold as a ledger reservation, and the one property that makes it safe to be one.
//!
//! The door's decision is the previous release's, and nothing added on top of it may change who
//! gets served. So every case here is about the same claim from a different angle: sizing a
//! reservation, growing one, and running past one are all ACCOUNTING, and none of the three has a
//! path that turns into a refusal. The last case says it directly — the door admits, the slice is
//! empty, the spend lands anyway.

use busbar_contract::caps::{
    step::Admit, AccrualRefused, Admittance, Exit, Grant, Hold, HoldCell, KernelSeal, Pass,
    PrincipalId,
};

use super::*;
use crate::{Admission as _, AdmissionUnit, ClassEstimate, Estimate};

/// The estimate of a unit expected to consume `quantity` of one class at `price` per unit.
fn estimate(quantity: u64, price: u64, fee_nanos: u64) -> Estimate {
    Estimate {
        per_class: vec![ClassEstimate {
            class: "tokens".to_string(),
            quantity,
            max_unit_price_nanos: price,
        }],
        fee_nanos,
    }
}

/// A chain with no spend cap anywhere has no ceiling a reservation could grow into, so the answer
/// is "as far as you like" rather than a figure. Reading it as zero would turn every over-running
/// unit on an uncapped deployment into an overdraft.
#[test]
fn an_uncapped_chain_has_unbounded_headroom() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 100, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_h", Some("g"));
    let now = 1_700_000_000;
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), None);
    let unit = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit.headroom_nanos(&c), u64::MAX);
}

/// The headroom is what the tightest capped bucket has left, and it shrinks as the window fills.
/// It is a read: asking for it charges nothing, so asking twice gives the same answer.
#[test]
fn headroom_is_what_the_tightest_capped_bucket_has_left() {
    let d = door();
    // 10 micro-units per input token: 100_000 input tokens is 100 cents.
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Budget, 1_000, Some(MONTH)),
                limit(LimitMetric::Budget, 100, Some(DAY)),
            ],
        ),
    )]);
    let c = chain(&t, "vk_h2", Some("g"));
    let now = 1_700_000_000;
    // The day cap is the tighter of the two, and nothing is spent yet.
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), Some(100));
    d.record_usage(&c, "", "m", &toks(60_000, 0), now); // 60 cents
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), Some(40));
    assert_eq!(
        d.budget_headroom_cents(&p, &c, "", now),
        Some(40),
        "reading the headroom charges nothing"
    );
    let unit = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit.headroom_nanos(&c), 40 * 10_000_000);
}

/// The headroom read has the same straddle arm as the check and the charge: a concurrent admission
/// can roll the cell into the live window before this read's pinned epoch catches up, and the read
/// has to follow it there rather than treat the rolled cell as an empty, fresh window.
///
/// Regressing the read's `>=` to `==` against the live cell's `window_start` would make a
/// straddling read of a spent window answer with the FULL cap rather than what is left — a unit
/// reading its headroom one tick before a boundary would see room that a request landing one tick
/// later, on the same cell, would already have spent.
#[test]
fn headroom_follows_a_straddling_cell_into_the_live_window() {
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Budget, 100, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_h_straddle", Some("g"));

    let later = 1_700_000_100;
    let earlier = 1_700_000_099;
    assert_ne!(
        crate::window::budget_window(MINUTE, earlier),
        crate::window::budget_window(MINUTE, later),
        "the two epochs have to be in different minutes for this to be a straddle at all"
    );

    // A concurrent admission rolls the cell into the newer minute and spends 60 of the 100 cents.
    d.record_usage(&c, "", "m", &toks(60_000, 0), later);

    // A headroom read pinned to the OLDER minute must still see that spend, not the full cap.
    assert_eq!(
        d.budget_headroom_cents(&p, &c, "", earlier),
        Some(40),
        "the straddling read must follow the live cell, not treat it as an untouched fresh window"
    );
}

/// A window already at its cap has nothing left to grow a reservation into, and says so as zero.
/// Zero is a top-up that does not happen; the next case is what it means for the unit.
#[test]
fn a_spent_window_reports_zero_headroom_rather_than_a_refusal() {
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_h3", Some("g"));
    let now = 1_700_000_000;
    d.record_usage(&c, "", "m", &toks(150_000, 0), now); // 150 cents against a 100-cent cap
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), Some(0));
    let unit = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit.headroom_nanos(&c), 0);
}

/// The reservation is sized off the estimate and the chain's tier, and the door's answer carries
/// it. Nothing about the size is a decision: a bigger estimate is a bigger hold, not a refusal.
#[test]
fn the_door_sizes_the_reservation_off_the_estimate() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let d = door();
    let p = no_card(0);
    let t = table(&[("g", group_cfg(None, true, Vec::new()))]);
    let c = chain(&t, "vk_h4", Some("g"));
    let mut unit = AdmissionUnit::new(&d, &p, "", 1_700_000_000);
    let who = PrincipalId::new("vk_h4");
    let decision = unit.admit(
        &estimate(1_000, 7, 500),
        &who,
        &c,
        &admit,
        &Pass::<Admit>::mint(&seal),
    );
    let admission = decision
        .into_result(&seal)
        .expect("nothing in this chain refuses");
    match admission {
        busbar_contract::caps::Admission::Own(hold) => {
            // 1_000 x 7 + 500 = 7_500, at the neutral tier.
            assert_eq!(hold.reserved(), 7_500);
            assert_eq!(hold.accrued(), 0);
            let _ = busbar_contract::caps::Posted::settle(
                hold,
                0,
                &busbar_contract::caps::Usage::report(
                    &busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(
                        &seal,
                    ),
                    Vec::new(),
                )
                .expect("no lines"),
                &busbar_contract::caps::Grant::<busbar_contract::caps::WriteMoney>::mint(&seal),
            );
        }
        other => panic!("a priced unit opens a hold of its own, got {other:?}"),
    }
}

/// **The property.** A unit the decision admits is never refused by anything the hold does.
///
/// The chain here is at its spend cap for tokens already ledgered, but the request counter and the
/// prospective-spend check both pass — which is exactly the case where the previous release served
/// the request. The unit is admitted, its reservation is far too small, the slice has nothing to
/// grow it with, and the spend still lands in full as an overdraft the unit carries out.
#[test]
fn a_unit_the_door_admits_is_never_refused_by_hold_sizing() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 10, Some(MINUTE))],
        ),
    )]);
    let capped = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let now = 1_700_000_000;
    let who = PrincipalId::new("vk_h5");
    // Fill the capped chain's window past its cap, so the headroom read is zero.
    let spent = chain(&capped, "vk_h5", Some("g"));
    d.record_usage(&spent, "", "m", &toks(200_000, 0), now);

    // The decision the previous release made: a requests limit this unit is under. It admits.
    let c = chain(&t, "vk_h5", Some("g"));
    let mut unit = AdmissionUnit::new(&d, &p, "", now);
    let admission = unit
        .admit(
            &estimate(1, 1, 0),
            &who,
            &c,
            &admit,
            &Pass::<Admit>::mint(&seal),
        )
        .into_result(&seal)
        .expect("the door admits: the unit is under every configured limit");

    let busbar_contract::caps::Admission::Own(mut hold) = admission else {
        panic!("a priced unit opens a hold of its own");
    };
    assert_eq!(
        hold.reserved(),
        1,
        "a reservation sized off a tiny estimate"
    );

    // The slice the top-up would come from is empty. There is no arm here that refuses: the spend
    // lands, in full, and what nothing could back is carried.
    let unit_on_spent = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit_on_spent.headroom_nanos(&spent), 0);
    let spend = unit_on_spent.spend(&mut hold, &spent, 9_000);
    assert_eq!(spend.accrued, 9_000);
    assert_eq!(spend.topped_up, 0);
    assert_eq!(spend.overdraft, 8_999);
    assert_eq!(hold.accrued(), 9_000);

    let usage = busbar_contract::caps::Usage::report(
        &busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(&seal),
        vec![busbar_contract::caps::UsageLine {
            class: busbar_contract::caps::MeterClassId::new("tokens"),
            quantity: 9_000,
            source: busbar_contract::caps::QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");
    let posted = busbar_contract::caps::Posted::settle(
        hold,
        9_000,
        &usage,
        &busbar_contract::caps::Grant::<busbar_contract::caps::WriteMoney>::mint(&seal),
    );
    assert_eq!(posted.settled(), 9_000, "the unit ran and posted in full");
    assert_eq!(posted.overdraft(), 8_999);
    assert!(posted
        .flags()
        .contains(busbar_contract::caps::PostingFlags::OVERDRAFT));
}

/// A reservation that turns out too small and a slice that CAN cover it grows rather than carries.
/// The overdraft is the last resort, not the ordinary path.
#[test]
fn a_reservation_that_can_grow_grows_instead_of_carrying() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_h6", Some("g"));
    let now = 1_700_000_000;
    let mut hold = Hold::open(&admit, PrincipalId::new("vk_h6"), 1_000);
    let unit = AdmissionUnit::new(&d, &p, "", now);
    // 100 cents of headroom is a billion nano-units: far more than the shortfall.
    let spend = unit.spend(&mut hold, &c, 5_000);
    assert_eq!(spend.topped_up, 4_000);
    assert_eq!(spend.overdraft, 0);
    assert_eq!(hold.reserved(), 5_000);
    let _ = busbar_contract::caps::Posted::settle(
        hold,
        0,
        &busbar_contract::caps::Usage::report(
            &busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(&seal),
            Vec::new(),
        )
        .expect("no lines"),
        &busbar_contract::caps::Grant::<busbar_contract::caps::WriteMoney>::mint(&seal),
    );
}

// ── a child spending against its parent's reservation ───────────────────────────────────────────

/// The setup for one child admission: the parent cell it attaches to, and the principal the CHILD
/// claims.
///
/// The child is admitted in every one of the cases below. The decision is the previous release's,
/// and nothing about a parent's hold may turn a yes into a no. What differs between them is what the
/// caller is told afterwards.
struct ParentCase {
    cell: HoldCell,
    child: PrincipalId,
}

/// Settle a hold a test is done with, rather than dropping money on the floor.
fn settle(hold: Hold, seal: &KernelSeal) {
    let _ = busbar_contract::caps::Posted::settle(
        hold,
        0,
        &busbar_contract::caps::Usage::report(
            &busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(seal),
            Vec::new(),
        )
        .expect("an empty report is within the bound"),
        &busbar_contract::caps::Grant::<busbar_contract::caps::WriteMoney>::mint(seal),
    );
}

/// A cell already admitted for `parent_who`, with its displaced arrival hold settled.
fn admitted_cell(
    parent_who: &PrincipalId,
    seal: &KernelSeal,
    admit: &Grant<Admittance>,
) -> HoldCell {
    let cell = HoldCell::new(crate::arrival_hold(parent_who.clone(), admit));
    let arrival = cell
        .admit(Hold::open(admit, parent_who.clone(), 10_000), admit)
        .expect("a fresh cell takes its admitted hold");
    settle(arrival, seal);
    cell
}

/// A cell whose arrival hold is still in the slot: the parent has not reached the door.
fn parent_not_admitted(admit: &Grant<Admittance>) -> ParentCase {
    let who = PrincipalId::new("vk_par");
    ParentCase {
        cell: HoldCell::new(crate::arrival_hold(who.clone(), admit)),
        child: who,
    }
}

/// A cell admitted for one principal, with the child claiming a different one.
fn parent_principal_mismatch(seal: &KernelSeal, admit: &Grant<Admittance>) -> ParentCase {
    ParentCase {
        cell: admitted_cell(&PrincipalId::new("vk_par"), seal, admit),
        child: PrincipalId::new("vk_other"),
    }
}

/// A cell whose hold has already been taken: the parent has exited.
fn parent_exited(seal: &KernelSeal, admit: &Grant<Admittance>) -> ParentCase {
    let who = PrincipalId::new("vk_par");
    let cell = admitted_cell(&who, seal, admit);
    let taken = cell
        .take(&Grant::<Exit>::mint(seal))
        .expect("the parent exits");
    settle(taken, seal);
    ParentCase { cell, child: who }
}

/// A cell admitted for the same principal the child claims: the accrual succeeds.
fn parent_ready(seal: &KernelSeal, admit: &Grant<Admittance>) -> ParentCase {
    let who = PrincipalId::new("vk_par");
    ParentCase {
        cell: admitted_cell(&who, seal, admit),
        child: who,
    }
}

/// Run one child admission against a parent cell and report both halves of the answer: what the
/// child was admitted with, and what the diagnostic seam says afterwards.
fn run_child(case: &ParentCase) -> (busbar_contract::caps::Admission, Option<AccrualRefused>) {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 100, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, case.child.as_str(), Some("g"));
    let mut unit = AdmissionUnit::new(&d, &p, "", 1_700_000_000).with_parent(&case.cell);
    let decision = unit.admit(
        &estimate(100, 7, 0),
        &case.child,
        &c,
        &admit,
        &Pass::<Admit>::mint(&seal),
    );
    let admission = decision
        .into_result(&seal)
        .expect("nothing in this chain refuses a child");
    (admission, unit.parent_accrual_refused())
}

/// A PARENT THAT HAS ALREADY EXITED IS THE ORDINARY RACE, AND IS REPORTED AS NOTHING.
///
/// This is the case the design plans for: the parent went, the child posts late on its own against a
/// synchronous draw, and there is no defect to tell anybody about. The child is admitted with a hold
/// of its own and the diagnostic seam stays empty.
#[test]
fn a_parent_that_exited_falls_through_silently() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let case = parent_exited(&seal, &admit);
    let (admission, refused) = run_child(&case);
    match admission {
        busbar_contract::caps::Admission::Own(hold) => settle(hold, &seal),
        other => panic!("the child is admitted and opens its own hold, got {other:?}"),
    }
    assert_eq!(
        refused, None,
        "an exited parent is the planned race, not a condition to report"
    );
}

/// A PARENT THAT HAS NOT PASSED THE DOOR IS AN ORDERING DEFECT, AND IS SURFACED.
///
/// The child still runs — the decision admitted it — but the caller ran a child ahead of its
/// parent's admission, and swallowing that leaves an ordering bug with no symptom anywhere.
#[test]
fn a_parent_not_yet_admitted_is_surfaced_and_the_child_still_runs() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let case = parent_not_admitted(&admit);
    let (admission, refused) = run_child(&case);
    match admission {
        busbar_contract::caps::Admission::Own(hold) => settle(hold, &seal),
        other => panic!("the child is admitted regardless, got {other:?}"),
    }
    assert_eq!(refused, Some(AccrualRefused::ParentNotAdmitted));
    let arrival = case
        .cell
        .take(&Grant::<Exit>::mint(&seal))
        .expect("the parent's arrival hold is still there");
    settle(arrival, &seal);
}

/// A PRINCIPAL MISMATCH IS A MISATTRIBUTION, AND IS SURFACED.
///
/// A child attached to somebody else's parent would, had the accrual gone through, have landed one
/// principal's spend on another's reservation. The runtime seal stops it; this is what makes the
/// stop visible instead of silent.
#[test]
fn a_principal_mismatch_is_surfaced_and_the_child_still_runs() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let case = parent_principal_mismatch(&seal, &admit);
    let (admission, refused) = run_child(&case);
    match admission {
        busbar_contract::caps::Admission::Own(hold) => settle(hold, &seal),
        other => panic!("the child is admitted regardless, got {other:?}"),
    }
    assert_eq!(refused, Some(AccrualRefused::PrincipalMismatch));
    // The parent's reservation is untouched: the mismatch accrued nothing into it.
    let parent = case
        .cell
        .take(&Grant::<Exit>::mint(&seal))
        .expect("the parent still holds");
    assert_eq!(parent.accrued(), 0, "nothing landed on the wrong parent");
    settle(parent, &seal);
}

/// The path that works: a matching, admitted parent takes the accrual, the child carries an accrual
/// rather than a hold of its own, and there is nothing to report.
#[test]
fn a_ready_parent_takes_the_accrual_and_reports_nothing() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let case = parent_ready(&seal, &admit);
    let (admission, refused) = run_child(&case);
    match admission {
        busbar_contract::caps::Admission::Accrual(accrual) => {
            assert_eq!(accrual.principal(), &case.child);
            assert_eq!(
                accrual.amount(),
                700,
                "quantity x price at the neutral tier"
            );
        }
        other => panic!("a child with a live parent spends against it, got {other:?}"),
    }
    assert_eq!(refused, None);
    let parent = case
        .cell
        .take(&Grant::<Exit>::mint(&seal))
        .expect("the parent still holds");
    assert_eq!(parent.accrued(), 700, "the child's spend landed on it");
    settle(parent, &seal);
}

// ── a parent that exits while its child still runs (owner ruling Q71(4)) ───────────────────────

/// Admit a child against a still-open parent through the door, then let the parent exit. Hands
/// back the child's outstanding accrual, the unit that admitted it, and the chain it was judged on.
fn child_outliving_its_parent<'r>(
    d: &'r Door<InMemoryCells>,
    p: &'r Pricer,
    parent: &'r HoldCell,
    c: &BucketChain,
    now: u64,
) -> (
    busbar_contract::caps::HoldAccrual,
    AdmissionUnit<'r, InMemoryCells>,
) {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let who = PrincipalId::new("vk_par");
    let mut unit = AdmissionUnit::new(d, p, "", now).with_parent(parent);
    let accrual = match unit
        .admit(
            &estimate(100, 7, 0),
            &who,
            c,
            &admit,
            &Pass::<Admit>::mint(&seal),
        )
        .into_result(&seal)
        .expect("the door admits the child")
    {
        busbar_contract::caps::Admission::Accrual(accrual) => accrual,
        other => panic!("the child spends against its open parent, got {other:?}"),
    };
    let taken = parent
        .take(&Grant::<Exit>::mint(&seal))
        .expect("the parent exits while the child still runs");
    settle(taken, &seal);
    (accrual, unit)
}

/// A PARENT THAT EXITS UNDER A RUNNING CHILD LEAVES THE CHILD HOLDING ITS OWN RESERVATION.
///
/// The accrual was spent against the parent's hold, and that hold has gone. The child's accrual
/// converts to a hold of the child's own, sized at what the child pushed and drawn against the
/// principal's slice, so what the child spends from here is bounded by a reservation instead of
/// posting late against nothing.
#[test]
fn a_child_whose_parent_exits_converts_its_accrual_to_its_own_hold() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let d = door();
    let p = no_card(10);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 30, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_par", Some("g"));
    let parent = admitted_cell(&PrincipalId::new("vk_par"), &seal, &admit);
    let now = 1_700_000_000;
    let (accrual, mut unit) = child_outliving_its_parent(&d, &p, &parent, &c, now);
    assert_eq!(accrual.amount(), 700, "100 units at 7 nano-units each");
    // The child's admission charged one fee: 10 of 30 cents spent, 20 left to draw against.
    let sized = unit
        .at_parent_exit(&accrual, &c)
        .expect("20 cents of headroom backs a 700 nano-unit hold");
    assert_eq!(sized, 700);
    let hold = accrual.convert_at_parent_exit(sized, &admit);
    assert_eq!(hold.principal().as_str(), "vk_par");
    assert_eq!(
        hold.reserved(),
        700,
        "the child now holds its own reservation"
    );
    assert_eq!(unit.blocked(), None);
    settle(hold, &seal);
}

/// A CONVERTED HOLD THE SLICE CANNOT BACK IS REFUSED ON THE BUDGET — THE DOOR'S OWN BUDGET BLOCK.
///
/// The one refusal this conversion adds (owner-accepted, Q71(4)). It is the budget family and
/// nothing new: the blocked bucket is exactly the one the door itself names when that bucket's
/// budget stops the next request, so it renders through the same text ("You have exceeded your
/// current quota (group 'g' budget per day exhausted). …") and the same over-budget code.
#[test]
fn a_converted_hold_the_slice_cannot_back_is_refused_on_the_budget() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    let d = door();
    let p = no_card(10);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 20, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_par", Some("g"));
    let parent = admitted_cell(&PrincipalId::new("vk_par"), &seal, &admit);
    let now = 1_700_000_000;
    let (accrual, mut unit) = child_outliving_its_parent(&d, &p, &parent, &c, now);
    // A sibling spends the slice to its cap: 20 of 20 cents, nothing left to back the child.
    drop(d.try_admit(&p, &c, "", now).expect("spend 10, +10 <= 20"));
    let refusal = unit
        .at_parent_exit(&accrual, &c)
        .expect_err("a slice at its cap cannot back the child's own hold");
    assert_eq!(
        refusal.reason(),
        busbar_contract::caps::ReasonCode::OverBudget
    );
    let door_says = d
        .try_admit(&p, &c, "", now)
        .expect_err("the door blocks the next request on the same bucket");
    let retry = crate::window_end(DAY, now).expect("a day window rolls") - now;
    let expected = Blocked::Limit {
        group: "g".to_string(),
        metric: Metric::Budget,
        window: Some(DAY),
        pool: None,
        downgrade_to: None,
        retry_after: Some(retry),
    };
    assert_eq!(door_says, expected);
    assert_eq!(unit.blocked(), Some(&expected));
    assert_eq!(Metric::Budget.as_str(), "budget");
    assert_eq!(refusal.retry_after_secs(), u32::try_from(retry).ok());
    // Refused, the accrual is still spend that happened: it posts late, never vanishes.
    let _ = busbar_contract::caps::Posted::settle_late(
        accrual,
        &busbar_contract::caps::Grant::<busbar_contract::caps::WriteMoney>::mint(&seal),
    );
}
