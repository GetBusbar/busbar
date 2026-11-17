// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::cost::CostModel;
use crate::governance::GovState;
use crate::persistence::host_records::tests::{attach, Backend};
use crate::persistence::observations::ObservationStore;
use crate::plane_driver::{Checkpoint, EndPost, FeeRefund, MoneySeam, UnitMoney};
use busbar_contract::json;
use busbar_contract::{records::VirtualKey, Count};
use std::collections::BTreeMap;

struct Post;
impl EndPost for Post {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
}
struct Pool;
impl Offload for Pool {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
    fn run_async(&self, job: AsyncJob) {
        tokio::spawn(job);
    }
}
fn cost(rate: u64) -> Arc<CostModel> {
    let rates = BTreeMap::from([(
        "serving".to_owned(),
        crate::config::RateEntryCfg {
            units: BTreeMap::from([
                (
                    "work_units".to_owned(),
                    busbar_kernel_ledger::cost::UnitRate::from_whole_micros(rate).unwrap(),
                ),
                (
                    "other_units".to_owned(),
                    busbar_kernel_ledger::cost::UnitRate::from_whole_micros(rate).unwrap(),
                ),
            ]),
            ..Default::default()
        },
    )]);
    let groups = BTreeMap::from([(
        "group".to_owned(),
        GroupCfg {
            enabled: true,
            limits: vec![LimitCfg {
                selected: None,
                metric: LimitMetric::Budget,
                amount: 1,
                per: Some(LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    Arc::new(CostModel::resolve_parts(Some(&rates), 0, &groups))
}
fn admitted(
    money: &PlaneMoney,
    gov: &GovState,
    cost: Arc<CostModel>,
    key: Arc<VirtualKey>,
    unit: u64,
) {
    let grant = Arc::new(gov.try_admit(&cost, &key, "", 100).unwrap());
    money.open_admitted(
        UnitKey::new(unit),
        UnitMoney {
            key,
            cost,
            pool: String::new(),
            lane: "serving".into(),
            classes: Arc::from(vec!["work_units".into(), "other_units".into()]),
            arrived: 100,
            mode: crate::config::groups::ExhaustionMode::FinishUnit,
            fee: FeeRefund::CallerStatus,
            charge: grant.charge().clone(),
        },
        grant,
    );
}
async fn scope_request(
    kernel: &KernelServices,
    caller: &Caller,
    ticket: Ticket,
    unit: u64,
    request: ScopeRequest,
) -> Result<Vec<u8>, &'static str> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    kernel
        .usage_observation_scope(
            caller,
            ticket,
            Some(unit),
            request,
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
        )
        .unwrap();
    rx.await.unwrap()
}
async fn submit(
    kernel: &KernelServices,
    caller: &Caller,
    ticket: Ticket,
    unit: u64,
    observation: Observation,
) -> wire::Receipt {
    let (tx, rx) = tokio::sync::oneshot::channel();
    kernel
        .usage_observation_submit(
            caller,
            ticket,
            Some(unit),
            observation,
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
        )
        .unwrap();
    let bytes = rx.await.unwrap().unwrap();
    json::parse(extensions::unique(&bytes, wire::RESULT).unwrap().unwrap()).unwrap()
}

#[tokio::test]
async fn neutral_runtime_custody_reserves_settles_and_reattaches_original_tariff() {
    let core = Arc::new(attach(Arc::new(Backend::default())).await);
    let gov = Arc::new(
        GovState::new_with_core(core.clone(), None, None)
            .await
            .unwrap(),
    );
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Post)));
    let key = Arc::new(VirtualKey {
        id: "owner".into(),
        enabled: true,
        group: Some("group".into()),
        ..Default::default()
    });
    let original_cost = cost(1);
    admitted(&money, &gov, original_cost.clone(), key.clone(), 1);
    let kernel = KernelServices::new().with_pool(Arc::new(Pool));
    kernel.units().admitted(
        1,
        crate::host_units::UnitRecord {
            principal: Some(key.clone()),
            depth: 0,
        },
    );
    let caller = Caller::for_test("fixture".into(), KindCode::Plane);
    let ticket = Ticket {
        slot: 1,
        generation: 1,
    };
    let policy = ObservationPolicy {
        instance: "fixture".into(),
        destination: "member".into(),
        serving_subject: "serving".into(),
        accounting_namespace: "account".into(),
        classes: vec![0],
        rated_subjects: vec![],
        reserve_nanos: 10_000_000,
        ordered_revisions: true,
    };
    assert!(kernel
        .usage_observation_input(&caller, ticket, Some(1))
        .is_none());
    kernel
        .register_observation_unit(&caller, UnitKey::new(1), money.clone(), policy.clone())
        .unwrap();
    assert!(wire::supported(
        &kernel
            .usage_observation_input(&caller, ticket, Some(1))
            .unwrap()
    )
    .unwrap());
    let forged = Caller::for_test("fixture".into(), KindCode::Plane);
    assert!(kernel
        .usage_observation_input(&forged, ticket, Some(1))
        .is_none());
    assert_eq!(
        scope_request(
            &kernel,
            &caller,
            ticket,
            1,
            ScopeRequest::create_requiring([0, 1])
        )
        .await,
        Err(REFUSED)
    );
    assert!(money.observation_scope(UnitKey::new(1)).is_none());
    assert!(gov
        .check_observation_admission(&original_cost, &key, "", 100)
        .await
        .is_ok());
    scope_request(
        &kernel,
        &caller,
        ticket,
        1,
        ScopeRequest::create_requiring([0]),
    )
    .await
    .unwrap();
    let id = wire::scope(
        &kernel
            .usage_observation_input(&caller, ticket, Some(1))
            .unwrap(),
    )
    .unwrap()
    .unwrap();
    assert!(gov
        .check_observation_admission(&original_cost, &key, "", 100)
        .await
        .is_err());
    let observation = Observation::new(id, b"event".to_vec(), b"part".to_vec())
        .count(0, Count::from(20))
        .unwrap()
        .revision(vec![1], 1)
        .final_totals();
    assert!(
        !submit(&kernel, &caller, ticket, 1, observation.clone())
            .await
            .duplicate
    );
    assert!(
        submit(
            &kernel,
            &caller,
            Ticket {
                slot: 2,
                generation: 1
            },
            1,
            observation.clone()
        )
        .await
        .duplicate
    );
    let ctx = crate::teller::UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(1),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: crate::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    assert_eq!(
        money.checkpoint(
            &ctx,
            &[busbar_contract::abi::plane::UnitCount {
                class: 0,
                source: busbar_contract::abi::plane::UNITS_REPORTED,
                amount: 20,
            }]
        ),
        Checkpoint::Unpriced
    );
    scope_request(&kernel, &caller, ticket, 1, ScopeRequest::close(id))
        .await
        .unwrap();
    assert_eq!(
        wire::result(
            &kernel
                .usage_observation_input(&caller, ticket, Some(1))
                .unwrap()
        )
        .unwrap(),
        Some(wire::ObservationResult::ScopeReady {
            scope: id,
            closed: true
        })
    );
    assert!(gov
        .check_observation_admission(&original_cost, &key, "", 100)
        .await
        .is_ok());
    let owner = ObservationStore::open(core).unwrap();
    let bound = owner
        .bind_scope(
            id,
            crate::persistence::observations::PrincipalBinding {
                principal: key.id.clone(),
                instance: policy.instance.clone(),
                destination: policy.destination.clone(),
                accounting_namespace: policy.accounting_namespace.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        owner.dated_total(&bound, 0).await.unwrap().spent_nanos,
        20_000
    );
    admitted(&money, &gov, cost(90), key.clone(), 2);
    kernel.units().admitted(
        2,
        crate::host_units::UnitRecord {
            principal: Some(key),
            depth: 0,
        },
    );
    kernel
        .register_observation_unit(
            &caller,
            UnitKey::new(2),
            money.clone(),
            ObservationPolicy {
                classes: vec![0, 1],
                ..policy
            },
        )
        .unwrap();
    // Current policy and current rates cover class 1, but original custody did not.
    assert_eq!(
        scope_request(
            &kernel,
            &caller,
            ticket,
            2,
            ScopeRequest::attach_requiring(id, [0, 1])
        )
        .await,
        Err(REFUSED)
    );
    scope_request(
        &kernel,
        &caller,
        ticket,
        2,
        ScopeRequest::attach_requiring(id, [0]),
    )
    .await
    .unwrap();
    let corrected = Observation::new(id, b"event".to_vec(), b"part".to_vec())
        .count(0, Count::from(12))
        .unwrap()
        .revision(vec![2], 2)
        .final_totals();
    submit(&kernel, &caller, ticket, 2, corrected).await;
    assert_eq!(
        owner.dated_total(&bound, 0).await.unwrap().spent_nanos,
        12_000
    );
    assert_eq!(owner.binding(&bound).await.unwrap().rate_time, 100);
    assert!(money
        .attach_observation_scope(
            UnitKey::new(2),
            &ObservationPolicy {
                accounting_namespace: "other".into(),
                ..kernel
                    .observation_context(&caller, Some(2))
                    .unwrap()
                    .policy
                    .clone()
            },
            id
        )
        .await
        .is_err());
}
