// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_services::Signing;
use crate::trust::book::Ruling;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::InstanceDecl;
use busbar_contract::services::{HostServices, Ran};

const INSTANCE: &str = "section-admission";

#[tokio::test]
async fn conditional_optional_admission_keeps_guards_without_requiring_unused_storage() {
    let services = KernelServices::new();
    assert!(!services.supports_record_transactions());
    let mut declaration = InstanceDecl {
        label: Arc::from(INSTANCE),
        record_kinds: vec!["sample"],
        conditional_records: true,
        conditional_record_kinds: vec![0],
        ..Default::default()
    };
    let section = busbar_contract::yaml::Value::Null;
    assert!(prepare_admission(&declaration, &services, ("sample", &section)).is_err());
    declaration.conditional_records_optional = true;
    let prepared = prepare_admission(&declaration, &services, ("sample", &section)).unwrap();
    assert_eq!(prepared.facts.conditional_record_kinds, vec![0]);
    prepared.commit().await.unwrap();
    assert!(!services.supports_record_transactions());
    declaration.conditional_records = false;
    assert!(prepare_admission(&declaration, &services, ("sample", &section)).is_err());
}
const MECHANISMS: &[PinMechanismDecl] = &[PinMechanismDecl {
    token: "rooted",
    root: true,
    peer_key: false,
}];

fn declaration() -> InstanceDecl {
    InstanceDecl {
        label: Arc::from(INSTANCE),
        record_kinds: vec!["sample"],
        signing: Some(("section-admission-domain", "sample-")),
        scope_kinds: vec!["peer"],
        trust_keys: vec![TrustKeyDecl {
            key: "pin",
            role: TrustRole::Pin,
            fingerprint: true,
            default: None,
            mechanisms: MECHANISMS,
        }],
        ..InstanceDecl::default()
    }
}

fn section(key: &str, max_live: usize) -> busbar_contract::yaml::Value {
    busbar_contract::yaml::from_str(&format!(
        "peer:\n  pin: {{mechanism: rooted, key: '{key}'}}\nwork: {{max_live: {max_live}, retain_s: 7}}"
    ))
    .expect("the section parses")
}

fn judge(services: &KernelServices) -> Result<(), Distrust> {
    services.trust_judge(
        INSTANCE,
        &TrustFacts {
            counterparty: "peer",
            item: None,
            digest: None,
        },
    )
}

async fn approve(services: &KernelServices) {
    let caller = Caller::for_test(Arc::from(INSTANCE), KindCode::Plane);
    let Ran::Now(answer) = services.trust_sight(
        &caller,
        "peer",
        "catalogue",
        Box::new(|_| panic!("an in-memory sighting does not pend")),
    ) else {
        panic!("an in-memory sighting completes inline");
    };
    assert_eq!(answer.outcome, AbiOutcome::Ready);
    services
        .trust_rule(&format!("{INSTANCE}/peer"), Ruling::Approve)
        .await
        .expect("the operator approves the sighted card");
    assert_eq!(judge(services), Ok(()));
}

async fn approved() -> KernelServices {
    let services = KernelServices::new();
    prepare_admission(&declaration(), &services, ("peers", &section("root-a", 32)))
        .unwrap()
        .commit()
        .await
        .unwrap();
    approve(&services).await;
    services
}

#[tokio::test]
async fn dropping_a_prepared_section_preserves_live_approval_and_work_bounds() {
    let services = approved().await;
    let before = services.trust_rows();
    let work = services.work_bounds_of(INSTANCE);
    let candidate =
        prepare_admission(&declaration(), &services, ("peers", &section("root-b", 64))).unwrap();
    assert_eq!(services.trust_rows(), before);
    assert_eq!(services.work_bounds_of(INSTANCE), work);
    drop(candidate);
    assert_eq!(services.trust_rows(), before);
    assert_eq!(services.work_bounds_of(INSTANCE), work);
    assert_eq!(judge(&services), Ok(()));
}

#[tokio::test]
async fn a_rejected_section_preserves_live_approval_and_work_bounds() {
    let services = approved().await;
    let before = services.trust_rows();
    let work = services.work_bounds_of(INSTANCE);
    let error = prepare_admission(&declaration(), &services, ("peers", &section("root-b", 0)))
        .err()
        .expect("a zero work bound is refused");
    assert!(error.contains("whole number above zero"), "{error}");
    assert_eq!(services.trust_rows(), before);
    assert_eq!(services.work_bounds_of(INSTANCE), work);
    assert_eq!(judge(&services), Ok(()));
}

#[tokio::test]
async fn a_refused_admission_commit_preserves_live_approval_and_work_bounds() {
    let services = approved().await;
    services
        .admit(
            "other",
            InstanceFacts {
                signing: Some(Signing {
                    domain: "held-domain".into(),
                    kid_prefix: "held-".into(),
                }),
                ..InstanceFacts::default()
            },
        )
        .await
        .unwrap();
    let before = services.trust_rows();
    let work = services.work_bounds_of(INSTANCE);
    let mut changed = declaration();
    changed.signing = Some(("held-domain", "sample-"));
    let candidate =
        prepare_admission(&changed, &services, ("peers", &section("root-b", 64))).unwrap();
    assert!(
        candidate.commit().await.is_err(),
        "the other instance owns its signing domain"
    );
    assert_eq!(services.trust_rows(), before);
    assert_eq!(services.work_bounds_of(INSTANCE), work);
    assert_eq!(judge(&services), Ok(()));
}

#[tokio::test]
async fn a_committed_section_keeps_same_pin_approval_and_requires_approval_for_a_new_pin() {
    let services = approved().await;
    let before = services.trust_rows();
    prepare_admission(&declaration(), &services, ("peers", &section("root-a", 48)))
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(services.trust_rows(), before);
    assert_eq!(services.work_bounds_of(INSTANCE).max_live, 48);
    assert_eq!(judge(&services), Ok(()));
    prepare_admission(&declaration(), &services, ("peers", &section("root-b", 64)))
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(services.work_bounds_of(INSTANCE).max_live, 64);
    assert_eq!(judge(&services), Err(Distrust::Unsighted));
    let rows = services.trust_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].approved, None);
    assert_eq!(rows[0].seen, None);
    approve(&services).await;
}
