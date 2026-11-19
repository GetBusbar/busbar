// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::plane::codes::ROUTE_SCOPE_LOCAL;
use busbar_contract::records::{ScopeRef, VirtualKey};

#[test]
fn an_unrelated_same_name_entry_keeps_its_primary_grant_boundary() {
    let catalog =
        busbar_contract::yaml::from_str("shared: { provider: catalog_provider }").unwrap();

    let section = busbar_contract::yaml::from_str(
        "session: { model: shared }\nmodels: { shared: { provider: unrelated_provider } }",
    )
    .unwrap();
    let (table, provenance) = routes_of(&section, Some(&catalog));
    assert!(provenance.is_none());
    assert_eq!(
        table.at("models").at("shared").at("provider").as_str(),
        Some("unrelated_provider")
    );
    let pools = DoorPools::of(&table, busbar_contract::section::RESERVED_POOLS_KEY).unwrap();
    let mut facts = door_facts(
        busbar_kernel::plane_driver::dispatch::LaneQualifier::parse("neutral").unwrap(),
        &["primary", "catalog"],
        &[],
        &[],
        "op",
        vec![],
    );

    facts
        .secondary_scopes
        .insert("shared".into(), "catalog".into());
    seal_secondary_scopes(
        &mut facts,
        &["primary", "catalog"],
        &pools,
        provenance.as_deref(),
    );
    assert!(facts.secondary_scopes.is_empty());
    let key = |kind: &str| VirtualKey {
        allowed_scopes: Some(vec![ScopeRef {
            kind: kind.into(),
            value: "shared".into(),
        }]),
        ..VirtualKey::default()
    };
    assert!(!facts.scope_candidate_granted(
        &pools,
        Some(&key("catalog")),
        ROUTE_SCOPE_LOCAL,
        true,
        "shared"
    ));
    assert!(facts.scope_candidate_granted(
        &pools,
        Some(&key("primary")),
        ROUTE_SCOPE_LOCAL,
        true,
        "shared"
    ));
}

#[test]
fn only_a_route_actually_synthesized_from_the_catalog_carries_provenance() {
    let catalog = busbar_contract::yaml::from_str(
        "shared: { provider: catalog_provider, upstream_model: upstream }",
    )
    .unwrap();
    let section = busbar_contract::yaml::from_str("session: { model: shared }").unwrap();
    let (table, provenance) = routes_of(&section, Some(&catalog));
    assert_eq!(provenance.as_deref(), Some("shared"));
    assert_eq!(
        table.at("models").at("shared").at("provider").as_str(),
        Some("catalog_provider")
    );
    assert_eq!(
        table
            .at("models")
            .at("shared")
            .at("upstream_model")
            .as_str(),
        Some("upstream")
    );
    for yaml in [
        "session: {}",
        "session: { model: missing }",
        "models: { shared: {} }",
    ] {
        let section = busbar_contract::yaml::from_str(yaml).unwrap();
        let (table, provenance) = routes_of(&section, Some(&catalog));
        assert!(provenance.is_none());
        assert_eq!(table, section);
    }
}
