// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST-ADMIN-PRODUCER-DESIGN r3 §3, §6 and tests G1, G12: the `core/trust` read surface.

use std::sync::Arc;

use busbar_contract::json::{JsonContainerTrait as _, JsonValueTrait as _};
use busbar_kernel::host_services::{InstanceFacts, KernelServices};
use busbar_kernel::trust::book::KeyState;
use busbar_kernel::trust::reverify::Policy;
use busbar_kernel::trust::section::TrustEntry;
use busbar_kernel::trust::TrustReadout;

use super::*;

fn entry(ttl_ms: u64, recovery_backoff_ms: u64) -> TrustEntry {
    TrustEntry {
        pin: None,
        policy: Policy {
            ttl_ms,
            recovery_backoff_ms,
        },
        approved: std::collections::BTreeMap::from([("tool".to_string(), "d1".to_string())]),
    }
}

async fn readout() -> TrustReadout {
    let kernel = KernelServices::new();
    kernel
        .admit(
            &"inst".into(),
            InstanceFacts {
                trust: vec![
                    ("cp".to_string(), entry(5_000, 100)),
                    ("other".to_string(), entry(2_000, 300)),
                ],
                ..InstanceFacts::default()
            },
        )
        .await
        .expect("admitted");
    TrustReadout::over(Arc::new(kernel))
}

#[test]
fn trust_state_enum_is_frozen() {
    let words: Vec<&str> = [
        KeyState::New,
        KeyState::Approved,
        KeyState::Same,
        KeyState::Drifted,
        KeyState::Quarantined,
    ]
    .iter()
    .map(|state| state.word())
    .collect();
    assert_eq!(words, KEY_STATES);
    assert_eq!(
        KEY_STATES,
        ["new", "approved", "same", "drifted", "quarantined"],
        "adding or renaming a trust state is a contract change"
    );
}

#[test]
fn the_four_views_are_declared_in_order() {
    let names: Vec<String> = descriptors()
        .iter()
        .map(|d| d["view"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(names, VIEWS);
}

#[tokio::test]
async fn without_custody_nothing_answers_empty() {
    assert!(
        trust_list_body(None).is_err(),
        "no empty success for GET /trust"
    );
    assert!(state(None).is_null());
    assert_eq!(custody(None).0, "failed");
    for view in VIEWS {
        assert!(
            matches!(rows(None, view).await, Some(Err(_))),
            "`{view}` is unavailable"
        );
    }
    assert!(rows(None, "nope").await.is_none());
}

#[tokio::test]
async fn one_projection_feeds_get_trust_and_the_views() {
    let readout = readout().await;
    let body: Value = json::parse_value(&trust_list_body(Some(&readout)).expect("served"))
        .expect("the body is JSON");
    let listed = body["keys"].as_array().expect("keys").clone();
    let mut from_views = Vec::new();
    for view in ["subjects", "items"] {
        for row in rows(Some(&readout), view)
            .await
            .expect("a view")
            .expect("served")
        {
            let mut keys = json::Map::new();
            for member in [
                "key",
                "instance",
                "counterparty",
                "item",
                "state",
                "approved",
                "seen",
            ] {
                keys.insert(member, row[member].clone());
            }
            from_views.push(Value::from(keys));
        }
    }
    let key_of = |v: &Value| v["key"].as_str().unwrap_or_default().to_string();
    let mut listed_keys: Vec<String> = listed.iter().map(key_of).collect();
    let mut view_keys: Vec<String> = from_views.iter().map(key_of).collect();
    listed_keys.sort();
    view_keys.sort();
    assert_eq!(listed_keys, view_keys, "GET /trust = subjects ∪ items");
    for row in &from_views {
        let same = listed.iter().find(|l| key_of(l) == key_of(row));
        assert_eq!(same, Some(row), "every key reads the same on both surfaces");
    }
}

#[tokio::test]
async fn state_carries_exactly_the_closed_members() {
    let readout = readout().await;
    let state = state(Some(&readout));
    let mut members: Vec<String> = state
        .as_object()
        .expect("an object")
        .iter()
        .map(|(k, _)| k.to_string())
        .collect();
    members.sort();
    assert_eq!(members, ["generation", "reverify", "standing"]);
    assert_eq!(state["reverify"]["ttl_ms"].as_u64(), Some(2_000));
    assert_eq!(state["reverify"]["recovery_backoff_ms"].as_u64(), Some(300));
    assert_eq!(
        state["standing"]["snapshot_generation"], state["generation"],
        "standing compares against the trust registry generation"
    );
}

#[tokio::test]
async fn an_unbound_kernel_serves_subjects_but_not_decisions() {
    let readout = readout().await;
    assert_eq!(custody(Some(&readout)).0, "failed");
    assert!(matches!(
        rows(Some(&readout), "subjects").await,
        Some(Ok(_))
    ));
    assert!(matches!(
        rows(Some(&readout), "decisions").await,
        Some(Err(_))
    ));
    assert!(matches!(
        rows(Some(&readout), "documents").await,
        Some(Err(_))
    ));
}
