// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Identity, then grant ([`validate_visibility`]), the generation source and the
//! standing-permission primitive. The identity-and-grant cases are set up so that BOTH steps would
//! refuse, and assert the EARLIEST one answers: the only shape of assertion a re-ordering breaks.

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

/// The happy path, so every refusal below is a difference from something that works.
#[test]
fn a_live_granted_caller_is_admitted() {
    let k = granting();
    let grants = [Grant::Scope {
        kind: "thing",
        name: "one",
    }];
    assert_eq!(validate_visibility(Some(&k), 100, &grants), Ok(()));
}

/// STEP 1 BEFORE STEP 2: the key is expired AND ungranted, and identity is the step that answers.
#[test]
fn identity_is_asked_before_the_grant() {
    let mut k = key(None); // wildcard scopes: the grant below would otherwise pass
    k.expires_at = Some(50);
    let grants = [Grant::Scope {
        kind: "thing",
        name: "nobody-holds-this",
    }];
    let refusal = validate_visibility(Some(&k), 100, &grants).expect_err("both steps refuse");
    assert_eq!(refusal.step(), 1, "identity is the first step");
    assert_eq!(refusal.reason(), reason::IDENTITY_NOT_LIVE);
}

/// `not_granted` and `egress_denied` are TWO WORDS, and they stay two: one is fixed on the caller's
/// key and the other on the target's standing list.
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

/// AN EMPTY EGRESS LIST IS NOBODY, never everybody.
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

/// GOVERNANCE DISABLED: with no principal there is no scope grant to narrow, and the target's own
/// standing egress list still applies.
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

/// THE GENERATION SOURCE is monotonic and never answers 0, so `0` stays usable as "nothing
/// selected".
#[test]
fn the_generation_source_is_monotonic_and_never_zero() {
    let a = next_generation();
    let b = next_generation();
    assert!(a >= 1);
    assert!(b > a);
}

/// THE STANDING PERMISSION holds an ID, not a principal. This is the whole of the fix: the value
/// handed back is re-resolved, so a key changed underneath an open response is seen.
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

/// A GENERATION MOVE lapses a standing permission, and the bound lapses it too. Both without any
/// governance runtime, because neither answer depends on one.
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

/// FAIL CLOSED when the principal cannot be re-resolved. A principal that was enforced at open and
/// cannot be found now is not one the next frame may be written under.
///
/// RED: answer `Ok(None)` for an unresolvable id and this returns `Ok`.
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

/// A WATCHING RESPONSE IS NOT LAPSED BY A MOVE. A subscription exists to REPORT the move; ending it
/// on one would make the feature refuse itself the moment it had something to say.
///
/// RED: make `Snapshot::Watching` compare the generation and the stream closes on its first event.
#[test]
fn a_watching_standing_permission_survives_a_generation_move() {
    let standing = Standing::opened(None, Snapshot::Watching, Duration::from_secs(300));
    assert_eq!(standing.still_permitted(None, 9_999, 0), Ok(None));
}

/// With governance disabled there is no principal to re-resolve and the permission stands.
#[test]
fn an_ungoverned_standing_permission_needs_no_reresolution() {
    let standing = Standing::opened(None, Snapshot::PinnedTo(3), Duration::from_secs(300));
    assert_eq!(standing.still_permitted(None, 3, 0), Ok(None));
}

// ── THE KEY-FREEZE HOLE, CLOSED AND PROVEN AGAINST A REAL REGISTRY ──────────────────────────────
//
// These drive the real `GovState` — a real store, a real `create_key`, the real `update_key` and
// `delete_key` an admin request calls — rather than a fixture that answers `None` on cue. A double
// that returned "not found" would pass on a `Standing` that never looked anything up, which is the
// exact defect being fixed.
//
// THE DEFECT: a `GovCtx` cloned into a long-lived response carries an `Arc<VirtualKey>` resolved at
// ingress. The catalogue behind such a response is re-read per frame, so a revoked APPROVAL bites
// within one poll — but the KEY is a copy, so a key deleted, disabled or re-scoped does not bite at
// all. It was survivable only because the response is capped at five minutes.

fn a_registry() -> std::sync::Arc<crate::governance::GovState> {
    std::sync::Arc::new(
        crate::governance::GovState::new(
            std::sync::Arc::new(crate::governance::MemoryStore::new()),
            None,
        )
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

/// THE CONTROL. Nothing has changed, so the standing permission stands and hands back the principal
/// AS IT IS NOW. Without this half, every assertion below would pass on a `Standing` that lapses
/// unconditionally.
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

/// DISABLING THE KEY BITES ON THE NEXT ASK.
///
/// RED, WATCHED: hold the `VirtualKey` on the `Standing` and answer from it — which is what
/// `gov: ctx.gov.clone()` did — and this returns `Ok`, because the copy taken at open is still
/// `enabled: true` for the whole life of the response.
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
    // The copy taken at open is untouched and still says `enabled`. That is precisely why holding it
    // would have been wrong, and asserting it here is what makes the test above about the LOOKUP
    // rather than about the argument.
    assert!(key.enabled);
}

/// DELETING THE KEY BITES TOO, and it is a separate case: a tombstoned row survives forever so
/// billing and audit keep resolving it, which means liveness is the check and the row's existence is
/// not.
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

/// RE-SCOPING THE KEY IS SEEN, and this is the half a liveness check alone would miss: the key is
/// still live, so the permission still STANDS — and the principal handed back is the NARROWED one,
/// which is what the next frame's grant is read from.
///
/// Returning the re-resolved key rather than a bare `Ok(())` is what makes this true; a caller told
/// "still permitted" and left to read its own copy would answer the old scopes.
#[test]
fn a_rescoped_key_is_handed_back_narrowed_rather_than_as_it_was_at_open() {
    let gov = a_registry();
    let key = a_live_key(&gov);
    assert!(
        key.allowed_scopes.is_none(),
        "the fixture starts as the store's wildcard"
    );
    let standing = Standing::opened(Some(&key), Snapshot::Watching, Duration::from_secs(300));

    // Narrow it under the open response, through the store the registry reads.
    let mut narrowed = gov.lookup_by_sub(&key.id).expect("live").as_ref().clone();
    narrowed.allowed_scopes = Some(vec![ScopeRef {
        kind: "thing".to_string(),
        value: "one".to_string(),
    }]);
    // Written through the SAME store the registry reads and reconciled the same way an admin write
    // reconciles. Not a poke at a cache: a test that patched the index directly would pass on a
    // `Standing` that read a cache nothing keeps current.
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
