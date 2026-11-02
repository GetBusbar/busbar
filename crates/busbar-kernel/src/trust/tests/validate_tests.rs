// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::trust::validate::{
    next_generation, reason, validate_visibility, Grant, Lapsed, Refusal, Snapshot, Standing,
};
use busbar_contract::records::{ScopeRef, VirtualKey};
use std::collections::BTreeMap;
use std::time::Duration;

fn key(scopes: Option<Vec<ScopeRef>>) -> VirtualKey {
    VirtualKey {
        id: "k1".to_string(),
        name: "k1".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: scopes,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
        ..Default::default()
    }
}

fn granting() -> VirtualKey {
    key(Some(vec![ScopeRef {
        kind: "thing".to_string(),
        value: "one".to_string(),
    }]))
}

#[test]
fn a_live_granted_caller_is_admitted() {
    let k = granting();
    let grants = [Grant::Scope {
        kind: "thing",
        name: "one",
    }];
    assert_eq!(validate_visibility(Some(&k), 100, &grants), Ok(()));
}

#[test]
fn identity_is_asked_before_the_grant() {
    let mut k = key(None);
    k.expires_at = Some(50);
    let grants = [Grant::Scope {
        kind: "thing",
        name: "nobody-holds-this",
    }];
    let refusal = validate_visibility(Some(&k), 100, &grants).expect_err("both steps refuse");
    assert_eq!(refusal.step(), 1, "identity is the first step");
    assert_eq!(refusal.reason(), reason::IDENTITY_NOT_LIVE);
}

#[test]
fn the_two_grant_refusals_stay_distinguishable() {
    let k = key(None);
    let allowed = vec!["someone-else".to_string()];
    let grants = [Grant::Egress {
        from: "me",
        allowed: &allowed,
    }];
    let refusal = validate_visibility(Some(&k), 100, &grants).expect_err("not on the list");
    assert_eq!(refusal.step(), 2);
    assert_eq!(refusal.reason(), reason::EGRESS_DENIED);
    assert_ne!(reason::EGRESS_DENIED, reason::NOT_GRANTED);
    assert_ne!(
        reason::NOT_GRANTED,
        crate::audit::vocab::REASON_UPSTREAM_FAILED
    );
    let narrow = granting();
    let ungranted = [Grant::Scope {
        kind: "thing",
        name: "two",
    }];
    assert_eq!(
        validate_visibility(Some(&narrow), 100, &ungranted)
            .expect_err("not granted")
            .reason(),
        reason::NOT_GRANTED
    );
}

#[test]
fn an_empty_egress_list_grants_nobody() {
    let k = key(None);
    let grants = [Grant::Egress {
        from: "me",
        allowed: &[],
    }];
    assert_eq!(
        validate_visibility(Some(&k), 100, &grants)
            .expect_err("empty is nobody")
            .reason(),
        reason::EGRESS_DENIED
    );
}

#[test]
fn an_ungoverned_caller_holds_every_scope_but_not_a_closed_egress_list() {
    let scope = [Grant::Scope {
        kind: "thing",
        name: "anything",
    }];
    assert_eq!(validate_visibility(None, 100, &scope), Ok(()));
    let egress = [Grant::Egress {
        from: "me",
        allowed: &[],
    }];
    assert!(matches!(
        validate_visibility(None, 100, &egress),
        Err(Refusal::EgressDenied { .. })
    ));
}

#[test]
fn the_generation_source_is_monotonic_and_never_zero() {
    let a = next_generation();
    let b = next_generation();
    assert!(a >= 1);
    assert!(b > a);
}

#[test]
fn a_standing_permission_stores_no_principal() {
    let k = granting();
    let standing = Standing::opened(Some(&k), Snapshot::PinnedTo(3), Duration::from_secs(300));
    let rendered = format!("{standing:?}");
    assert!(
        rendered.contains("k1"),
        "the ID is what is kept: {rendered}"
    );
    assert!(
        !rendered.contains("generation_hash"),
        "a VirtualKey was carried into the standing permission: {rendered}"
    );
}

#[test]
fn a_standing_permission_lapses_on_a_generation_move_and_on_its_bound() {
    let k = granting();
    let standing = Standing::opened(Some(&k), Snapshot::PinnedTo(3), Duration::from_secs(300));
    assert_eq!(
        standing.still_permitted(None, 4, 0),
        Err(Lapsed::Generation(Refusal::GenerationMoved {
            admitted: 3,
            live: 4
        }))
    );

    let expired = Standing::opened(Some(&k), Snapshot::PinnedTo(3), Duration::ZERO);
    assert_eq!(expired.still_permitted(None, 3, 0), Err(Lapsed::Expired));
}

#[test]
fn a_principal_that_cannot_be_reresolved_lapses() {
    let k = granting();
    let standing = Standing::opened(Some(&k), Snapshot::PinnedTo(3), Duration::from_secs(300));
    assert_eq!(
        standing.still_permitted(None, 3, 0),
        Err(Lapsed::Identity(Refusal::IdentityNotLive {
            principal: "k1".to_string()
        }))
    );
}

#[test]
fn a_watching_standing_permission_survives_a_generation_move() {
    let standing = Standing::opened(None, Snapshot::Watching, Duration::from_secs(300));
    assert_eq!(standing.still_permitted(None, 9_999, 0), Ok(None));
}

#[test]
fn an_ungoverned_standing_permission_needs_no_reresolution() {
    let standing = Standing::opened(None, Snapshot::PinnedTo(3), Duration::from_secs(300));
    assert_eq!(standing.still_permitted(None, 3, 0), Ok(None));
}

fn a_registry() -> std::sync::Arc<crate::governance::GovState> {
    std::sync::Arc::new(
        crate::governance::GovState::new(crate::real_store::store(), None)
            .expect("a memory-backed registry constructs"),
    )
}

fn a_live_key(gov: &crate::governance::GovState) -> VirtualKey {
    let (key, _secret) = gov
        .create_key(
            crate::governance::NewKeySpec {
                name: "streamer".to_string(),
                allowed_pools: None,
                group: None,
                labels: BTreeMap::new(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("mint");
    key
}

#[test]
fn a_standing_permission_reresolves_a_live_principal() {
    let gov = a_registry();
    let key = a_live_key(&gov);
    let standing = Standing::opened(Some(&key), Snapshot::Watching, Duration::from_secs(300));
    let resolved = standing
        .still_permitted(Some(&*gov), 1, 1_700_000_000)
        .expect("a live key still stands")
        .expect("a governed deployment resolves a principal");
    assert_eq!(resolved.id, key.id);
}

#[test]
fn a_key_disabled_under_an_open_response_lapses_it_on_the_next_ask() {
    let gov = a_registry();
    let key = a_live_key(&gov);
    let standing = Standing::opened(Some(&key), Snapshot::Watching, Duration::from_secs(300));
    assert!(standing
        .still_permitted(Some(&*gov), 1, 1_700_000_000)
        .is_ok());

    gov.update_key(&key.id, Some(false), None)
        .expect("the admin PATCH an operator makes")
        .expect("the key exists");

    assert_eq!(
        standing.still_permitted(Some(&*gov), 1, 1_700_000_000),
        Err(Lapsed::Identity(Refusal::IdentityNotLive {
            principal: key.id.clone()
        })),
        "the key the response was opened under is disabled and the response did not notice"
    );

    assert!(key.enabled);
}

#[test]
fn a_key_deleted_under_an_open_response_lapses_it_on_the_next_ask() {
    let gov = a_registry();
    let key = a_live_key(&gov);
    let standing = Standing::opened(Some(&key), Snapshot::Watching, Duration::from_secs(300));
    assert!(standing
        .still_permitted(Some(&*gov), 1, 1_700_000_000)
        .is_ok());

    gov.delete_key(&key.id).expect("the admin DELETE");

    assert_eq!(
        standing.still_permitted(Some(&*gov), 1, 1_700_000_000),
        Err(Lapsed::Identity(Refusal::IdentityNotLive {
            principal: key.id.clone()
        }))
    );
}

#[test]
fn a_rescoped_key_is_handed_back_narrowed_rather_than_as_it_was_at_open() {
    let gov = a_registry();
    let key = a_live_key(&gov);
    assert!(
        key.allowed_scopes.is_none(),
        "the fixture starts as the store's wildcard"
    );
    let standing = Standing::opened(Some(&key), Snapshot::Watching, Duration::from_secs(300));

    let mut narrowed = gov.lookup_by_sub(&key.id).expect("live").as_ref().clone();
    narrowed.allowed_scopes = Some(vec![ScopeRef {
        kind: "thing".to_string(),
        value: "one".to_string(),
    }]);

    gov.store().put_key(&narrowed).expect("store write");
    gov.refresh().expect("reconcile");

    let resolved = standing
        .still_permitted(Some(&*gov), 1, 1_700_000_000)
        .expect("a narrowed key is still a live key")
        .expect("a principal");
    assert!(resolved.scope_allowed("thing", "one"));
    assert!(
        !resolved.scope_allowed("thing", "two"),
        "the narrowing was not seen: the response is reading the copy taken at open"
    );
}
