// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the 1.5.3 named-DEFINITION map SECTION TABLE — the data description every
//! generic surface (router, OpenAPI, taxonomy, overlay) is parameterized by.

use super::*;
use crate::config::tests::base_deploy;

/// The path grammar is derived from ONE key per section, so the config key and the admin path
/// segment can never drift apart (`export:` ⇄ `/export`) — and every section's five routes parse
/// back to `(section, shape)` without a hand-written path list anywhere.
#[test]
fn every_section_round_trips_its_three_route_shapes() {
    for section in NamedMapSection::ALL {
        assert_eq!(
            section.path_root(),
            format!("/{}", section.key()),
            "the admin path segment IS the config key"
        );
        let root = section.path_root().to_string();
        assert_eq!(
            NamedMapSection::parse_rel(&root),
            Some((*section, NamedMapShape::Collection))
        );
        assert_eq!(
            NamedMapSection::parse_rel(&format!("{root}/{{name}}")),
            Some((*section, NamedMapShape::Item))
        );
        assert_eq!(
            NamedMapSection::parse_rel(&format!("{root}/{{name}}/settings")),
            Some((*section, NamedMapShape::Settings))
        );
        // A path that merely SHARES the prefix is not a named-map route.
        assert_eq!(
            NamedMapSection::parse_rel(&format!("{root}/{{name}}/health")),
            None
        );
    }
    // Sections the generic CRUD deliberately does NOT serve.
    assert_eq!(NamedMapSection::parse_rel("/hooks"), None);
    assert_eq!(NamedMapSection::parse_rel("/groups/{name}"), None);
}

/// A definition is parsed into its typed, `deny_unknown_fields` config struct at the insert seam —
/// so an unknown key is rejected by the API exactly as `config.yaml` would reject it, and the
/// overlay can never hold a definition a reload would refuse.
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

/// The dangling-reference guard: `referents` names every OTHER config site that still references a
/// definition by bare name, which is what makes a delete-that-would-dangle a precise, actionable
/// terminal conflict rather than a late `resolve` failure.
#[test]
fn referents_finds_every_bare_name_reference_site() {
    let mut deploy = base_deploy();
    deploy.identity_providers.insert(
        "corp-ad".into(),
        serde_json::from_value(serde_json::json!({"module": "ad"})).unwrap(),
    );
    let mut auth = crate::config::AuthDeployCfg {
        chain: vec!["keys".into(), "corp-ad".into()],
        admin_auth: vec!["admin-tokens".into(), "corp-ad".into()],
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
    // An exporter is a LEAF in 1.5.3 — nothing references it by name, so nothing can dangle.
    assert!(NamedMapSection::Export
        .referents(&deploy, "metrics")
        .is_empty());
}

/// Only `identity-providers:` carries a TRUST CEILING. The predicate — not a `match` at the call
/// site — is what keeps the admin handler generic while still enforcing the ceiling rule.
#[test]
fn only_identity_providers_carry_a_trust_ceiling() {
    assert!(NamedMapSection::IdentityProviders.has_trust_ceiling());
    assert!(!NamedMapSection::Export.has_trust_ceiling());
}
