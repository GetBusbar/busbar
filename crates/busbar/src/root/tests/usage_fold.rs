// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SP-M1: a unit's final usage is folded once, at the meter gate, and carried to the late
//! accrual's report and the settlement. Driven at the money seam in the order a unary unit runs
//! it: the plane's checkpoint, `DriverSteps::meter` (the gate), `report_of` (the late accrual's
//! report, `LateAccrual::post`) and `settle_end_as` (the root's settlement).

use std::sync::Arc;

use busbar_contract::abi::plane::{UnitCount, ROUTE_POOL, UNITS_REPORTED};
use busbar_contract::caps::{Outcome, PrincipalId, ReasonCode};
use busbar_contract::stage_probe::{Derive, Scope};
use busbar_contract::Count;
use busbar_kernel::plane_driver::{DriverSteps as _, EndPost, MoneySeam as _, PlaneMoney, UnitEnd};

use crate::root::door_steps::tests::{downgrade_book, pools, DOWNGRADE_SECTION};

/// More declared classes than one usage report holds (`MAX_USAGE_LINES` is 16).
const SEVENTEEN: [&str; 17] = [
    "c00", "c01", "c02", "c03", "c04", "c05", "c06", "c07", "c08", "c09", "c10", "c11", "c12",
    "c13", "c14", "c15", "c16",
];

fn reported(class: u32, amount: u64) -> UnitCount {
    UnitCount {
        class,
        source: UNITS_REPORTED,
        amount,
    }
}

/// One admitted unit's money and steps, over the real governor.
struct Unit {
    app: Arc<busbar_kernel::state::App>,
    key: Arc<busbar_contract::records::VirtualKey>,
    facts: super::DoorFacts,
    money: PlaneMoney,
    kernel: busbar_kernel::teller::Kernel,
    arrived: u64,
}

async fn unit(classes: &[&'static str]) -> Unit {
    let (app, key) = downgrade_book(Vec::new(), None).await;
    let facts = super::door_facts("", &["pool"], classes, &[], "door", Vec::new());
    let gov = Arc::clone(app.governance.as_ref().expect("actual governance"));
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(Arc::new(
        crate::root::plane_node::Node::new(),
    )));
    let money = PlaneMoney::new(gov, post as Arc<dyn EndPost>);
    Unit {
        app,
        key,
        facts,
        money,
        kernel: busbar_kernel::teller::Kernel::new(),
        arrived: busbar_kernel::store::now(),
    }
}

/// Drive one unit: admit it, report `first`, meter it, optionally report `late` after the meter
/// (an SSE stream whose final usage arrives after route end), then report and settle it.
/// Returns the meter's answer and the late accrual's report.
fn drive(
    u: &Unit,
    unit: u64,
    first: &[UnitCount],
    late: Option<&[UnitCount]>,
    scope: &Scope,
) -> (
    Result<busbar_contract::caps::Usage, busbar_contract::caps::Refusal>,
    Option<crate::root::linked::node::Reported>,
) {
    let pools = pools(DOWNGRADE_SECTION);
    let principal = PrincipalId::new(u.key.id.as_str());
    let steps = super::DoorSteps::new(
        &u.facts,
        &pools,
        Arc::new(|_: &str| None),
        Arc::clone(&u.app),
        Some(&u.money),
        super::DoorCaller {
            principal: principal.clone(),
            key: Some(Arc::clone(&u.key)),
            open: false,
            arrived: u.arrived,
            records: None,
            depth: 0,
            credential: None,
            ticket: None,
        },
    );
    steps.lock().routed = pools.resolve(ROUTE_POOL, Some(b"frontier"));
    let ctx = busbar_kernel::teller::UnitCtx {
        call: u.kernel.next_call(),
        key: busbar_contract::UnitKey::new(unit),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let admission = steps
        .admit(
            &u.kernel.admit_token_for(ctx.call),
            &ctx,
            &principal,
            &[],
            &Default::default(),
        )
        .expect("the unit is admitted");
    assert_eq!(scope.count(Derive::UsageFold), 0, "admission folds nothing");

    let _ = u.money.checkpoint(&ctx, first);
    let metered = steps.meter(&u.kernel.usage_token(), &ctx, &Outcome::Completed, &[]);
    if let Some(late) = late {
        let _ = u.money.checkpoint(&ctx, late);
    }
    let report = crate::root::serve::report_of(&u.money, ctx.key, &u.facts);
    let status = if metered.is_ok() { 200 } else { 402 };
    u.money.settle_end_as(
        ctx.key,
        UnitEnd {
            caller_status: status,
            cut: false,
            refused_unspent: false,
        },
    );
    drop(admission);
    drop(steps);
    (metered, report)
}

#[tokio::test]
async fn usage_folded_once() {
    let u = unit(&["input", "output"]).await;

    let scope = Scope::open();
    let (metered, report) = drive(&u, 9101, &[reported(0, 7), reported(1, 3)], None, &scope);
    let metered = metered.expect("the meter gate passes priced counts");
    assert_eq!(metered.lines().len(), 2, "one line per counted class");
    let (exact, fee, _lane, _) = report
        .and_then(crate::root::linked::node::Reported::legacy)
        .expect("the late accrual reports the unit");
    assert_eq!(exact.usage_units.get("input"), Some(&Count::from(7u64)));
    assert_eq!(exact.usage_units.get("output"), Some(&Count::from(3u64)));
    assert_eq!(fee, 0, "no fee unit declared");
    assert_eq!(
        scope.count(Derive::UsageFold),
        1,
        "meter folds the final counts once; report and settle carry its fold"
    );
    assert_eq!(
        scope.count(Derive::MoneyShardLock),
        3,
        "one shard lock each for meter, report and settle"
    );
    drop(scope);

    let scope = Scope::open();
    let (metered, report) = drive(
        &u,
        9102,
        &[reported(0, 7)],
        Some(&[reported(0, 7), reported(1, 11)]),
        &scope,
    );
    metered.expect("the meter gate passes the counts it saw");
    let (exact, _, _, _) = report
        .and_then(crate::root::linked::node::Reported::legacy)
        .expect("the late accrual reports the unit");
    assert_eq!(
        exact.usage_units.get("output"),
        Some(&Count::from(11u64)),
        "counts that moved after the meter are re-folded, never dropped"
    );
    assert!(
        scope.count(Derive::UsageFold) <= 2,
        "counts arriving after route end re-fold once: {}",
        scope.count(Derive::UsageFold)
    );
}

/// A unit whose counts the meter cannot price is refused `Unpriced` at the gate, from the same
/// fold the late accrual and the settlement then carry, and its settlement is not delivered.
///
/// A checked-sum overflow cannot be reached through a checkpoint (`adds_up` keeps every named
/// class within a 64-bit column, and `Count` sums in 128 bits), so this drives the gate's other
/// unpriceable report: more counted classes than one usage report holds. The audit and journal
/// seal of the refusal are the teller's (`under_hold`, `sealed_end`) and are not driven here.
#[tokio::test]
async fn overflow_unit_audited_unpriced_not_billed() {
    let u = unit(&SEVENTEEN).await;
    let counts: Vec<UnitCount> = (0..17u32).map(|class| reported(class, 1)).collect();

    let scope = Scope::open();
    let (metered, report) = drive(&u, 9201, &counts, None, &scope);
    let refusal = metered.expect_err("seventeen counted classes cannot be one usage report");
    assert_eq!(refusal.reason(), ReasonCode::Unpriced);
    let (exact, _, _, _) = report
        .and_then(crate::root::linked::node::Reported::legacy)
        .expect("the late accrual still reports what was counted");
    assert_eq!(exact.usage_units.len(), 17);
    assert_eq!(
        scope.count(Derive::UsageFold),
        1,
        "the refusing gate's fold is the one carried to report and settle"
    );
    assert_eq!(u.money.open_units(), 0, "the refused unit's end closes it");
}
