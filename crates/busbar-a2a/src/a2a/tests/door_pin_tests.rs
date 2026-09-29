// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE AND THE DOOR STATE THE SAME FACTS. While the engine still serves, its declaration,
//! its route table and its admin routes are written a second time in the door; these tests pin
//! the two equal, entry by entry, so neither drifts.

use super::*;
use busbar_contract::abi::cold::endpoint::RouteAuth;

#[test]
fn the_declaration_states_the_doors_nouns() {
    let d = &PLANE_DECLARATION;
    assert_eq!(d.scope_kinds, [door::SCOPE]);
    assert_eq!(d.subject_noun, config::SUBJECT_NOUN);
    assert_eq!(d.admin_noun, door::ADMIN_NOUN);
    assert_eq!(d.audit_kind, door::AUDIT_KIND);
    assert_eq!(d.card_signing_domain, Some(door::CARD_SIGNING_DOMAIN));
    assert_eq!(d.card_kid_prefix, Some(door::CARD_KID_PREFIX));
    assert_eq!(d.billable_classes.len(), 1);
    assert_eq!(d.billable_classes[0].family, door::BYTES_FAMILY);
    assert_eq!(d.fee_units, [door::FEE_PER_REQUEST]);
    assert_eq!(door::TAIL.record_kinds_len, d.record_kinds.len());
    assert_eq!(
        d.trust_keys.iter().map(|k| k.key).collect::<Vec<_>>(),
        config::TRUST_KEYS.iter().map(|k| k.key).collect::<Vec<_>>()
    );
    assert_eq!(door::TAIL.trust_keys_len, d.trust_keys.len());
}

#[test]
fn the_engines_routes_are_the_doors_routes_in_order() {
    let cfg = door::read_settings(
        br#"{"planner": {"url": "https://vendor.example/planner", "pin": {"mechanism": "unpinned"}}}"#,
    )
    .expect("a valid section");
    let plane =
        plane::A2aPlane::from_config(&cfg, Some("https://busbar.example")).expect("a plane");
    let engine: Vec<(&str, String, bool)> = receive::a2a_routes(plane.as_ref())
        .iter()
        .map(|r| (r.method.as_str(), r.path.clone(), r.auth == RouteAuth::None))
        .collect();
    let door: Vec<(&str, String, bool)> = door::ROUTES
        .iter()
        .map(|r| (r.verb, r.target.to_string(), r.open))
        .collect();
    assert_eq!(engine, door);
}

#[test]
fn the_engines_admin_routes_are_the_doors_admin_verbs() {
    let engine: Vec<(&str, String)> = admin_routes(&())
        .iter()
        .map(|r| (r.method.as_str(), r.path.clone()))
        .collect();
    let door: Vec<(&str, String)> = door::ADMIN_VERBS
        .iter()
        .map(|(v, t)| (*v, (*t).to_string()))
        .collect();
    assert_eq!(engine, door);
}

#[test]
fn the_engines_openapi_fragment_keys_the_doors_admin_verbs() {
    let doc = openapi_fragment();
    let keys: Vec<&String> = doc.as_object().expect("an object").keys().collect();
    assert_eq!(keys.len(), door::ADMIN_VERBS.len());
    for (_, target) in door::ADMIN_VERBS {
        assert!(
            keys.iter().any(|k| k.ends_with(target)),
            "{target} is missing from {keys:?}"
        );
    }
}
