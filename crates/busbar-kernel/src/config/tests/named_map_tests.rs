// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::tests::base_deploy;

#[test]
fn every_section_round_trips_its_three_route_shapes() {
    for section in NamedMapSection::sections() {
        assert_eq!(
            section.path_root().as_ref(),
            format!("/{}", section.key()),
            "the admin path segment IS the config key"
        );
        let root = section.path_root().to_string();
        assert_eq!(
            NamedMapSection::parse_rel(&root),
            Some((section, NamedMapShape::Collection))
        );
        assert_eq!(
            NamedMapSection::parse_rel(&format!("{root}/{{name}}")),
            Some((section, NamedMapShape::Item))
        );
        assert_eq!(
            NamedMapSection::parse_rel(&format!("{root}/{{name}}/settings")),
            Some((section, NamedMapShape::Settings))
        );

        assert_eq!(
            NamedMapSection::parse_rel(&format!("{root}/{{name}}/health")),
            None
        );
    }

    assert_eq!(NamedMapSection::parse_rel("/hooks"), None);
    assert_eq!(NamedMapSection::parse_rel("/groups/{name}"), None);
}

#[test]
fn insert_parses_the_typed_definition_and_rejects_an_unknown_field() {
    let mut deploy = base_deploy();
    NamedMapSection::IdentityProviders
        .insert(
            &mut deploy,
            "corp-ad",
            &serde_json::json!({"module": "ad", "max_admin_scope": "read-only"}),
        )
        .expect("a well-formed identity-provider definition is accepted");
    assert_eq!(deploy.identity_providers["corp-ad"].module, "ad");
    assert_eq!(
        deploy.identity_providers["corp-ad"]
            .max_admin_scope
            .as_deref(),
        Some("read-only")
    );

    let err = NamedMapSection::Export
        .insert(
            &mut deploy,
            "metrics",
            &serde_json::json!({"module": "prometheus", "modle": {}}),
        )
        .expect_err("a typo'd key must be rejected, never silently stored");
    assert!(
        err.contains("export.metrics"),
        "the error names the entry: {err}"
    );
}

#[test]
fn referents_finds_every_bare_name_reference_site() {
    let mut deploy = base_deploy();
    deploy.identity_providers.insert(
        "corp-ad".into(),
        serde_json::from_value(serde_json::json!({"module": "ad"})).unwrap(),
    );
    let mut auth = crate::config::AuthDeployCfg {
        chain: vec!["keys".into(), "corp-ad".into()],
        admin_auth: vec![crate::config::operator_provider().into(), "corp-ad".into()],
        ..Default::default()
    };
    auth.role_bindings
        .insert("corp-ad".into(), Default::default());
    deploy.auth = Some(auth);

    let refs = NamedMapSection::IdentityProviders.referents(&deploy, "corp-ad");
    assert_eq!(
        refs,
        vec![
            "auth.chain".to_string(),
            "auth.admin_auth".to_string(),
            "auth.role_bindings.corp-ad".to_string()
        ]
    );
    assert!(
        NamedMapSection::IdentityProviders
            .referents(&deploy, "unreferenced")
            .is_empty(),
        "an unreferenced definition dangles nothing"
    );

    assert!(NamedMapSection::Export
        .referents(&deploy, "metrics")
        .is_empty());
}

#[test]
fn only_identity_providers_carry_a_trust_ceiling() {
    assert!(NamedMapSection::IdentityProviders.has_trust_ceiling());
    assert!(!NamedMapSection::Export.has_trust_ceiling());
}

#[test]
fn a_section_no_registered_plane_declares_is_an_unknown_field() {
    let _isolation = crate::test_support::planes::TestRegistryIsolation::empty();
    let section = NamedMapSection::Plane("bays");
    let err = section
        .parse_def("dock", &serde_json::json!({}))
        .err()
        .expect("a section no plane declares is refused");
    assert_eq!(err, "unknown field `bays`");
    let err = section
        .insert(&mut base_deploy(), "dock", &serde_json::json!({}))
        .expect_err("and refused on insert too");
    assert_eq!(err, "unknown field `bays`");
    assert!(!err.contains("compiled without"), "{err}");
}
