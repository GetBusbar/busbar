// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The production [`UsageObservations`] over the kernel's observation custody (IF §12.4): scopes and observations
//! of the unit a verified principal has in flight, under the operator's policy.

use std::collections::BTreeMap;

use busbar_contract::abi::sdk::plane::observation::Receipt;
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;
use busbar_plugin_abi::plane::{
    OBS_ACCEPTED, OBS_ATTACH, OBS_CLOSE, OBS_CLOSED, OBS_CREATE, OBS_FINAL, OBS_PENDING,
    OBS_PROVISIONAL, OBS_READY, OBS_REFUSED,
};

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::cost::CostModel;
use crate::governance::GovState;
use crate::persistence::host_records::tests::{attach, Backend};
use crate::plane_driver::port_auth::subject_identity;
use crate::plane_driver::port_intents::Namespace;
use crate::plane_driver::{EndPost, FeeRefund, ObservationPolicy, PlaneMoney, UnitMoney};

struct Post;
impl EndPost for Post {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
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
                metric: LimitMetric::Budget,
                amount: 1,
                per: Some(LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    Arc::new(CostModel::resolve_parts(Some(&rates), 0, &groups))
}

fn who() -> Namespace {
    Namespace {
        plugin: "plane-fixture".into(),
        name: "fixture".into(),
        instance: 1,
        slot: 0,
    }
}

fn policy() -> ObservationPolicy {
    ObservationPolicy {
        instance: "fixture".into(),
        destination: "member".into(),
        serving_subject: "serving".into(),
        accounting_namespace: "account".into(),
        // Only class 0 (`work_units`) is priced under the operator's policy.
        classes: vec![0],
        rated_subjects: vec![],
        reserve_nanos: 10_000_000,
        ordered_revisions: true,
    }
}

struct Fixture {
    custody: ObsCustody,
    money: Arc<PlaneMoney>,
    registration: Registration,
}

async fn fixture() -> Fixture {
    let core = Arc::new(attach(Arc::new(Backend::default())).await);
    let gov = Arc::new(GovState::new_with_core(core, None, None).await.unwrap());
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Post)));
    let key = Arc::new(VirtualKey {
        id: "owner".into(),
        enabled: true,
        group: Some("group".into()),
        ..Default::default()
    });
    let cost = cost(1);
    let grant = Arc::new(gov.try_admit(&cost, &key, "", 100).unwrap());
    money.open_admitted(
        UnitKey::new(1),
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
    let custody = ObsCustody::new(Arc::new(|| 100_000));
    let registration = custody
        .register(
            "fixture",
            "owner",
            ActiveUnit {
                money: money.clone(),
                unit: UnitKey::new(1),
                policy: policy(),
                classes: Arc::from(vec!["work_units".to_owned(), "other_units".to_owned()]),
            },
        )
        .unwrap();
    Fixture {
        custody,
        money,
        registration,
    }
}

fn observation<'a>(
    scope: [u8; 32],
    state: u32,
    counts: &'a [(&'a str, u64, u32)],
) -> ObservationIn<'a> {
    ObservationIn {
        scope,
        event: b"event",
        component: b"part",
        revision: Some((&[1u8][..], 1)),
        state,
        counts,
        rated_subject: 0,
        evidence: b"",
    }
}

#[tokio::test]
async fn a_principal_with_no_unit_in_flight_has_no_custody() {
    let custody = ObsCustody::new(Arc::new(|| 1));
    let who = who();
    let owner = subject_identity("owner");
    assert_eq!(
        custody
            .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
    let counts = [("work_units", 20, 0)];
    let (status, receipt) = custody
        .observe(
            &who.caller(),
            &owner,
            &observation([7; 32], OBS_FINAL, &counts),
        )
        .await;
    assert_eq!(status, OBS_REFUSED);
    assert!(receipt.is_empty());
}

#[tokio::test]
async fn create_requires_the_classes_priced_then_observe_settles_once_and_close_closes() {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    // `other_units` is not priced in the operator's policy: refused before any money is reserved.
    assert_eq!(
        f.custody
            .scope(
                &who.caller(),
                &owner,
                OBS_CREATE,
                None,
                &["work_units", "other_units"]
            )
            .await,
        (OBS_REFUSED, None)
    );
    assert!(f.money.observation_scope(UnitKey::new(1)).is_none());
    let (status, id) = f
        .custody
        .scope(&who.caller(), &owner, OBS_CREATE, None, &["work_units"])
        .await;
    assert_eq!(status, OBS_READY);
    let id = id.expect("a READY answer names the scope");
    assert_eq!(f.money.observation_scope(UnitKey::new(1)), Some(id));

    let counts = [("work_units", 20, 0)];
    let first = f
        .custody
        .observe(&who.caller(), &owner, &observation(id, OBS_FINAL, &counts))
        .await;
    assert_eq!(first.0, OBS_ACCEPTED);
    let receipt: Receipt = busbar_contract::json::parse(&first.1).unwrap();
    assert!(!receipt.duplicate);
    let again = f
        .custody
        .observe(&who.caller(), &owner, &observation(id, OBS_FINAL, &counts))
        .await;
    assert_eq!(again.0, OBS_ACCEPTED);
    assert!(
        busbar_contract::json::parse::<Receipt>(&again.1)
            .unwrap()
            .duplicate
    );

    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_CLOSE, Some(id), &[])
            .await,
        (OBS_CLOSED, Some(id))
    );
}

#[tokio::test]
async fn attach_answers_the_bound_scope_and_another_scope_is_refused() {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    let (_, id) = f
        .custody
        .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
        .await;
    let id = id.unwrap();
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_ATTACH, Some(id), &[])
            .await,
        (OBS_READY, Some(id))
    );
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_ATTACH, Some([9; 32]), &[])
            .await,
        (OBS_REFUSED, None)
    );
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_ATTACH, None, &[])
            .await,
        (OBS_REFUSED, None),
        "an attach names its scope"
    );
}

#[tokio::test]
async fn custody_is_the_verified_principals_and_the_instances_only() {
    let f = fixture().await;
    let who = who();
    let counts = [("work_units", 1, 0)];
    // Another principal does not reach the owner's unit.
    let mallory = subject_identity("mallory");
    assert_eq!(
        f.custody
            .scope(&who.caller(), &mallory, OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
    assert_eq!(
        f.custody
            .observe(
                &who.caller(),
                &mallory,
                &observation([1; 32], OBS_PROVISIONAL, &counts)
            )
            .await
            .0,
        OBS_REFUSED
    );
    // Nor does another plane instance, nor a request with no subject.
    let other = Namespace {
        name: "other".into(),
        ..who
    };
    assert_eq!(
        f.custody
            .scope(
                &other.caller(),
                &subject_identity("owner"),
                OBS_CREATE,
                None,
                &[]
            )
            .await,
        (OBS_REFUSED, None)
    );
    assert_eq!(
        f.custody
            .scope(&self::who().caller(), &[], OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
}

#[tokio::test]
async fn a_class_the_unit_does_not_name_is_refused_and_so_is_an_unknown_state() {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_CREATE, None, &["nope"])
            .await,
        (OBS_REFUSED, None)
    );
    let (_, id) = f
        .custody
        .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
        .await;
    let id = id.unwrap();
    let nope = [("nope", 1, 0)];
    assert_eq!(
        f.custody
            .observe(&who.caller(), &owner, &observation(id, OBS_FINAL, &nope))
            .await
            .0,
        OBS_REFUSED
    );
    let counts = [("work_units", 1, 0)];
    assert_eq!(
        f.custody
            .observe(&who.caller(), &owner, &observation(id, 99, &counts))
            .await
            .0,
        OBS_REFUSED
    );
    assert_ne!(OBS_PENDING, OBS_REFUSED);
}

#[tokio::test]
async fn ending_the_request_releases_the_unit_and_a_policy_naming_another_instance_is_not_registered(
) {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    let Fixture {
        custody,
        money,
        registration,
    } = f;
    drop(registration);
    assert_eq!(
        custody
            .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
    let mut foreign = policy();
    foreign.instance = "elsewhere".into();
    assert!(custody
        .register(
            "fixture",
            "owner",
            ActiveUnit {
                money,
                unit: UnitKey::new(1),
                policy: foreign,
                classes: Arc::from(vec!["work_units".to_owned()]),
            },
        )
        .is_err());
}
