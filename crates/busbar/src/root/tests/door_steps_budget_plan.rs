// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-AD1: one admitted unit builds its budget inputs (expected units, estimate, the
//! key's budget chain) once, at `prepare_admission`, and carries them to its charge and its
//! settlement. A budget downgrade rebuilds them for the new route, as before. Counted by the
//! dev-only stage probes (`busbar_contract::stage_probe`) on the actual door steps and governor.

use super::{downgrade_book, downgrading, owned, pools, DOWNGRADE_SECTION};
use busbar_contract::abi::plane::{UnitCount, ROUTE_POOL, UNITS_REPORTED};
use busbar_contract::caps::PrincipalId;
use busbar_contract::stage_probe::{Derive, Scope};
use busbar_kernel::plane_driver::{DriverSteps as _, EndPost, MoneySeam as _, PlaneMoney};
use std::sync::Arc;

struct Driven {
    admitted: Result<(), busbar_contract::caps::ReasonCode>,
    routed: Option<(String, Vec<String>)>,
    downgraded: Option<String>,
}

/// Drive one keyed unit routed to `pool` through `prepare_admission` and `admit` on the actual
/// door steps, then (when `settle`) report its usage and settle it on the actual money book.
async fn drive(
    app: &Arc<busbar_kernel::state::App>,
    key: &Arc<busbar_contract::records::VirtualKey>,
    pool: &str,
    unit: u64,
    settle: bool,
) -> Driven {
    let pools = pools(DOWNGRADE_SECTION);
    let facts = super::super::door_facts(
        busbar_kernel::plane_driver::dispatch::LaneQualifier::parse("").unwrap(),
        &["pool"],
        &["input"],
        &[],
        "door",
        Vec::new(),
    );
    let gov = Arc::clone(app.governance.as_ref().expect("a governed generation"));
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(Arc::new(
        crate::root::plane_node::Node::new(),
    )));
    let money = PlaneMoney::new(gov, post as Arc<dyn EndPost>);
    let principal = PrincipalId::new(key.id.as_str());
    let steps = super::super::DoorSteps::new(
        &facts,
        &pools,
        Arc::new(|_: &str| None),
        Arc::clone(app),
        Some(&money),
        super::super::DoorCaller {
            principal: principal.clone(),
            key: Some(Arc::clone(key)),
            open: false,
            arrived: busbar_kernel::store::now(),
            records: None,
            depth: 0,
            credential: None,
            ticket: None,
        },
    );
    steps.lock().routed = pools.resolve(ROUTE_POOL, Some(pool.as_bytes()));
    let kernel = busbar_kernel::teller::Kernel::new();
    let ctx = busbar_kernel::teller::UnitCtx {
        call: kernel.next_call(),
        key: busbar_contract::UnitKey::new(unit),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let token = kernel.admit_token_for(ctx.call);
    let admitted = match steps.prepare_admission(&ctx, &principal, &[]).await {
        Ok(()) => steps
            .admit(&token, &ctx, &principal, &[], &Default::default())
            .map(|_| ())
            .map_err(|refusal| refusal.reason()),
        Err(refusal) => Err(refusal.reason()),
    };
    if settle && admitted.is_ok() {
        money.checkpoint(
            &ctx,
            &[UnitCount {
                class: 0,
                source: UNITS_REPORTED,
                amount: 7,
            }],
        );
        money.settle_end(ctx.key, 200);
    }
    Driven {
        admitted,
        routed: steps.routed(),
        downgraded: steps.downgraded(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn budget_plan_built_once() {
    let (app, key) = downgrade_book(vec![downgrading("frontier", 1_000, "value")], None).await;

    let scope = Scope::open();
    let driven = drive(&app, &key, "frontier", 1, true).await;

    assert_eq!(driven.admitted, Ok(()), "the keyed unit is admitted");
    assert_eq!(driven.downgraded, None, "no downgrade under the cap");
    assert_eq!(
        scope.count(Derive::BudgetUnits),
        1,
        "the unit's expected budget units are built once, at prepare_admission"
    );
    assert_eq!(
        scope.count(Derive::ChainFor),
        1,
        "the key's budget chain is resolved once; the observation check, the charge and the \
         settlement read the carried chain"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_downgrade_rebuilds_the_budget_plan_for_its_new_route() {
    let (app, key) = downgrade_book(vec![downgrading("frontier", 25, "value")], None).await;
    for unit in 1..=2 {
        let under = drive(&app, &key, "frontier", unit, false).await;
        assert_eq!(
            under.admitted,
            Ok(()),
            "unit {unit} is under the frontier cap"
        );
        assert_eq!(under.downgraded, None);
    }

    let scope = Scope::open();
    let driven = drive(&app, &key, "frontier", 3, false).await;

    assert_eq!(
        driven.admitted,
        Ok(()),
        "the observation check ran once, on the routed pool, and passed; the downgraded \
         charge is not refused by a second observation check for the new pool"
    );
    assert_eq!(driven.downgraded.as_deref(), Some("value"));
    assert_eq!(driven.routed, owned("value", &["small"]));
    assert_eq!(
        scope.count(Derive::BudgetUnits),
        1,
        "expected units do not depend on the route: built once and kept across the downgrade"
    );
    assert_eq!(
        scope.count(Derive::ChainFor),
        2,
        "the carried chain for the routed pool, then the downgrade re-admission's own"
    );
}
