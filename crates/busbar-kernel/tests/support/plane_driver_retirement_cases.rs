// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Worker results that arrive before the caller's next poll still belong to the sweep.

use super::*;

/// Poll only the caller until its real pump has submitted a pending crossing. No runtime clock
/// decides the race: the test then completes the worker's cancel and drops the unpolled caller.
async fn worker_cancel_before_caller_poll(member: &'static str) {
    let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let rows = Arc::new(AuditRows::default());
    r.driver = r.driver.with_audit(rows.clone());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&[member], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let mut running = Box::pin(cases::drive(&units));
    let ticket = std::future::poll_fn(|cx| {
        for _ in 0..32 {
            assert!(running.as_mut().poll(cx).is_pending());
            if let Some(ticket) = r.plane.held.lock().unwrap().keys().next().copied() {
                return Poll::Ready(ticket);
            }
        }
        panic!("the scripted pending crossing was never submitted");
    })
    .await;
    r.plane.drop_client(ticket);
    assert_eq!(r.stats()[stat::CANCELS], 1, "the worker cancelled once");
    drop(running);
    drop(units);
    assert_eq!(r.driver.buried(), 1);
    r.driver.sweep();
    assert_eq!(r.driver.buried(), 0);
    assert_eq!(r.stats()[stat::CANCELS], 1, "no second terminal cancel");
    let bills = r.book.bills();
    assert_eq!(bills.len(), 1);
    assert_eq!(bills[0].disposition, CANCEL_FAILED);
    let expected = if member == "hang-row" {
        vec![(
            "thing.cancel".to_string(),
            "thing:x".to_string(),
            busbar_contract::vocab::OUTCOME_APPLIED,
            common::principal().as_str().to_string(),
        )]
    } else {
        Vec::new()
    };
    assert_eq!(*rows.0.lock().unwrap(), expected);
    r.driver.sweep();
    assert_eq!(r.book.bills().len(), 1);
    assert_eq!(*rows.0.lock().unwrap(), expected);
}

#[tokio::test]
async fn an_unpolled_worker_cancel_keeps_its_disposition_and_record_writes() {
    worker_cancel_before_caller_poll("hang-row").await;
}

#[tokio::test]
async fn an_unpolled_worker_cancel_fault_is_not_cancelled_again() {
    worker_cancel_before_caller_poll("cancel-fault").await;
}

#[tokio::test]
async fn the_first_checkpoint_prices_its_answer_lane_on_the_admitted_card() {
    use busbar_kernel::config::groups::{
        ExhaustionMode, GroupCfg, LimitCfg, LimitMetric, LimitWindow,
    };
    use busbar_kernel::plane_driver::{EndPost, FeeRefund, PlaneMoney, UnitMoney};
    struct NoPost;
    impl EndPost for NoPost {
        fn post(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
    }
    const AT: u64 = 1_700_000_000;
    for (explicit, expensive) in [(true, false), (true, true), (false, false), (false, true)] {
        let lane = if explicit { "tool_x" } else { "ok" };
        let groups = std::collections::BTreeMap::from([(
            "g".to_string(),
            GroupCfg {
                enabled: true,
                limits: vec![LimitCfg {
                    metric: LimitMetric::Budget,
                    amount: 1,
                    per: Some(LimitWindow::Month),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                    admission: None,
                    on_exhaustion: None,
                }],
                ..Default::default()
            },
        )]);
        let rate = |expensive| busbar_kernel::config::RateEntryCfg {
            input_utok: if expensive { 100_000.0 } else { 1.0 },
            output_utok: 1.0,
            ..Default::default()
        };
        let card = std::collections::BTreeMap::from([
            ("m".to_string(), rate(!expensive)),
            (lane.to_string(), rate(expensive)),
        ]);
        let cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
            Some(&card),
            0,
            &groups,
        ));
        let gov = Arc::new(
            busbar_kernel::governance::GovState::new(Arc::new(MemoryStore::new()), None)
                .expect("governance"),
        );
        let key = Arc::new(busbar_contract::records::VirtualKey {
            id: "k".into(),
            generation_hash: "h:k".into(),
            name: "k".into(),
            enabled: true,
            group: Some("g".into()),
            revision: 1,
            ..Default::default()
        });
        let grant = gov.try_admit(&cost, &key, "", AT).expect("real admission");
        let money = Arc::new(PlaneMoney::new(gov, Arc::new(NoPost)));
        money.open(
            common::ctx(7).key,
            UnitMoney {
                key,
                cost,
                pool: String::new(),
                lane: "m".to_string(),
                classes: Arc::from(vec!["input".to_string()]),
                arrived: AT,
                mode: ExhaustionMode::CutStream,
                fee: FeeRefund::CallerStatus,
                charge: grant.charge().clone(),
            },
        );
        let r = rig(
            Way::Double,
            BufferCaps::default(),
            cases::Book::forwarding(money.clone()),
        );
        let (steps, far, caller) = (
            common::TestUnits::passing(),
            if explicit {
                cases::Far::new(&[], &[])
            } else {
                cases::Far::new(&["ok"], cases::CHUNKS)
            },
            cases::Caller::default(),
        );
        let target = if explicit { "/audit" } else { "/call" };
        let units = r
            .driver
            .unit(&steps, &far, &caller, cases::arrival(target, b"x"), 0);
        let outcome = cases::drive(&units).await;
        assert_eq!(money.serving(common::ctx(7).key).as_deref(), Some(lane));
        if expensive {
            assert!(
                matches!(
                    outcome,
                    busbar_contract::caps::Outcome::Failed(
                        _,
                        busbar_contract::caps::ReasonCode::OverBudget
                    )
                ),
                "{outcome:?}"
            );
        } else {
            assert_eq!(outcome, busbar_contract::caps::Outcome::Completed);
        }
        money.settle_end(common::ctx(7).key, if expensive { 429 } else { 200 });
        assert_eq!(money.open_units(), 0);
    }
}
