// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A parent unit that exits while its child still runs (owner ruling Q71(4)).
//!
//! The child's accrual was spent against the parent's hold, and that hold goes with the parent. The
//! loop converts the accrual to a hold of the child's own at the child's end, so the child settles
//! against a reservation instead of posting late against nothing — or, where the door cannot back
//! that hold, ends refused on the budget and its accrual still posts, late.

mod common;

use std::sync::Arc;

use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Audit, Authenticate, Canary, Consumption, Decision,
    Decode, Dial, Encode, Grant, HoldAccrual, HoldCell, HoldCellState, Meter, Outcome, Pass,
    PostingFlags, PrincipalId, ReasonCode, Refusal, Route, StepName, VerifiedDestination, Verify,
};
use busbar_kernel::slice::{ConcurrencyGauge, GroupLeaseSlip, LeaseCell};
use busbar_kernel::teller::{
    exit, run_unit, AccrualMeter, Ended, Evidence, Kernel, Run, UnitCtx, Units,
};

use common::{cell, ctx, principal, Door, TestUnits};

/// A child whose parent exits, through the real exit path, while the child's Route step runs.
struct ParentExitsMidRoute<'k> {
    child: TestUnits,
    kernel: &'k Kernel,
    parent: Arc<HoldCell>,
    /// What this door answers when asked to back the converted hold.
    door_backs: Option<ReasonCode>,
}

impl ParentExitsMidRoute<'_> {
    fn parent_exits(&self) {
        let (leases, gauge, meter) = (
            LeaseCell::new(),
            ConcurrencyGauge::new(),
            AccrualMeter::new(),
        );
        let ended = exit(
            self.kernel,
            &TestUnits::passing(),
            &ctx(7),
            Run {
                cell: &self.parent,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &Canary::new(),
                meter: &meter,
            },
            Outcome::Completed,
            true,
        );
        assert!(matches!(ended, Ended::Settled { .. }), "the parent exits");
    }
}

impl Units for ParentExitsMidRoute<'_> {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> Decision<Arrival> {
        self.child.arrival(token, ctx)
    }
    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> Decision<Decode> {
        self.child.decode(token, ctx)
    }
    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> Decision<Authenticate> {
        self.child.authenticate(token, ctx)
    }
    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        self.child.verify(token, trust, ctx, principal)
    }
    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        self.child.approve(token, ctx, principal, destinations)
    }
    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        self.child
            .admit(token, admit, ctx, principal, destinations, leases)
    }
    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        meter: &AccrualMeter,
        destinations: &[VerifiedDestination],
    ) -> Decision<Route> {
        let routed = self.child.route(token, ctx, meter, destinations);
        self.parent_exits();
        routed
    }
    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> Decision<Meter> {
        self.child
            .meter(token, usage, ctx, provisional, destinations)
    }
    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit> {
        self.child.audit(token, ctx, outcome)
    }
    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        self.child.audit_refused(token, ctx, refusal)
    }
    fn encode(&self, token: &Pass<Encode>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Encode> {
        self.child.encode(token, ctx, outcome)
    }
    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        self.child.evidence(ctx)
    }
    fn at_parent_exit(&self, _ctx: &UnitCtx, accrual: &HoldAccrual) -> Result<u64, Refusal> {
        match self.door_backs {
            None => Ok(accrual.amount()),
            Some(reason) => Err(Refusal::new(reason)),
        }
    }
}

/// Run a child that pushes 250 against an open parent and spends 400, whose parent exits while
/// its Route step runs. Hands back the end and the child's cell.
fn child_outliving_its_parent(door_backs: Option<ReasonCode>) -> (Ended, HoldCell, Canary) {
    let kernel = Kernel::new();
    let parent = Arc::new(cell(&kernel));
    let admitted = busbar_contract::caps::Hold::open(&kernel.admit_token(), principal(), 5_000);
    let _arrival = parent
        .admit(admitted, &kernel.admit_token())
        .expect("the parent's cell was fresh");
    let units = ParentExitsMidRoute {
        child: TestUnits {
            door: Door::Accrual(Arc::clone(&parent), 250),
            spend: 400,
            evidence: Evidence {
                located: Some(400),
                ..Evidence::default()
            },
            ..TestUnits::default()
        },
        kernel: &kernel,
        parent: Arc::clone(&parent),
        door_backs,
    };
    let child_cell = cell(&kernel);
    let (leases, gauge, meter, canary) = (
        LeaseCell::new(),
        ConcurrencyGauge::new(),
        AccrualMeter::new(),
        Canary::new(),
    );
    let ended = run_unit(
        &kernel,
        &units,
        &ctx(1),
        Run {
            cell: &child_cell,
            parent: Some(&parent),
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );
    assert_eq!(parent.state(), HoldCellState::Taken, "the parent exited");
    (ended, child_cell, canary)
}

/// THE CHILD'S ACCRUAL BECOMES ITS OWN HOLD. It settles against a reservation of 250 — what it
/// pushed — with only the spend past that carried as an overdraft, where it used to post the
/// whole accrual late against nothing (reserved 0, overdraft 250, LATE_ACCRUAL).
#[test]
fn a_parent_exit_converts_the_childs_accrual_to_its_own_hold() {
    let (ended, child_cell, canary) = child_outliving_its_parent(None);
    match ended {
        Ended::Settled { end, requests, fee } => {
            assert_eq!(end.outcome(), Outcome::Completed);
            let posted = end.posted().expect("the child posts like any other unit");
            assert_eq!(
                posted.reserved(),
                250,
                "the child holds its own reservation"
            );
            assert_eq!(posted.settled(), 400);
            assert_eq!(posted.overdraft(), 150, "only the spend past its own hold");
            assert!(!posted.flags().contains(PostingFlags::LATE_ACCRUAL));
            assert_eq!(
                (requests, fee),
                (0, 0),
                "a child draws no slot and posts no fee"
            );
        }
        other => panic!("expected a settled child, got {other:?}"),
    }
    assert_eq!(child_cell.state(), HoldCellState::Taken);
    assert_eq!(canary.counts().settlements, 1);
    assert_eq!(canary.balanced(), Ok(()));
}

/// A HOLD THE DOOR CANNOT BACK REFUSES THE CHILD ON THE BUDGET. The end is the door's refusal —
/// the over-budget code, at the admission step — and the accrual still posts, late: the spend
/// happened, and a refusal is never where money disappears.
#[test]
fn a_converted_hold_the_door_cannot_back_ends_the_child_over_budget() {
    let (ended, child_cell, canary) = child_outliving_its_parent(Some(ReasonCode::OverBudget));
    match ended {
        Ended::Settled { end, requests, fee } => {
            assert_eq!(
                end.outcome(),
                Outcome::Failed(StepName::Admit, ReasonCode::OverBudget)
            );
            let posted = end.posted().expect("the accrual still posts");
            assert_eq!((posted.reserved(), posted.settled()), (0, 250));
            assert!(posted.flags().contains(PostingFlags::LATE_ACCRUAL));
            assert_eq!((requests, fee), (0, 0));
        }
        other => panic!("expected a settled child, got {other:?}"),
    }
    assert_eq!(child_cell.state(), HoldCellState::Taken);
    assert_eq!(canary.balanced(), Ok(()));
}
