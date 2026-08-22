// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ORDER IS THE PROPERTY, so the assertions are about WHICH STEP refused rather than about
//! whether a bad request was refused.
//!
//! A test that only asserts "this is refused" passes on a validator whose four steps run in any
//! order, and passes on one that runs only the last of them. Every case below is set up so that
//! SEVERAL steps would refuse it, and asserts the EARLIEST one answers — which is the only shape of
//! assertion that a re-ordering breaks.
//!
//! ## The red proof each of these was watched to fail as
//!
//! Each `#[test]` names, in its own doc, the mutation that makes it fail. They were run: deleting
//! the identity block makes `identity_is_asked_before_the_grant` report step 2; moving the
//! fingerprint closure above the grant loop makes `an_ungranted_caller_never_causes_the_artifact_to
//! _be_read` see the counter at 1; deleting the generation comparison makes
//! `the_generation_is_the_last_step_and_it_exists` return `Ok`.

use super::*;
use crate::trust::validate::{
    next_generation, reason, validate_request, Ask, Fingerprint, Generations, Grant, Lapsed,
    Observed, Refusal, Snapshot, Standing,
};
use crate::trust::Observation;
use busbar_api::{ScopeRef, VirtualKey};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::time::Duration;

/// A two-part artifact, so nothing below can quietly assume a single-value pin.
#[derive(Clone, Debug, PartialEq)]
struct TwoPart {
    root: &'static str,
    body: &'static str,
}

impl PinnedArtifact for TwoPart {
    fn mechanism(&self) -> &'static str {
        "two_part"
    }
    fn digest(&self) -> String {
        format!("{}+{}", self.root, self.body)
    }
}

const PIN: TwoPart = TwoPart {
    root: "ROOT",
    body: "BODY",
};

fn seen(caps: &[(&str, &str)]) -> Sighting<TwoPart> {
    Sighting::Seen(Observation {
        pin: Some(PIN),
        capabilities: caps
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect::<BTreeMap<_, _>>(),
    })
}

/// An APPROVED registration serving one capability at `d1`.
fn approved() -> (Approval<TwoPart>, Sighting<TwoPart>) {
    let sighting = seen(&[("work", "d1")]);
    let mut approval = Approval::registered();
    approval.approve(&sighting, None).expect("approve");
    (approval, sighting)
}

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
fn a_request_that_passes_every_step_is_admitted() {
    let (approval, sighting) = approved();
    let k = granting();
    let observe = || Observed::At("d1".to_string());
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[Grant::Scope {
            kind: "thing",
            name: "one",
        }],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::at_admission(7),
    };
    assert_eq!(validate_request(&ask), Ok(()));
}

/// STEP 1 BEFORE STEP 2. The key is expired AND ungranted AND the registration is suspended AND the
/// generation has moved: four steps would refuse it and identity must be the one that does.
///
/// RED: delete the identity block from `validate_request` and this reports step 2.
#[test]
fn identity_is_asked_before_the_grant() {
    let (mut approval, sighting) = approved();
    approval.suspend("operator");
    let mut k = key(None); // wildcard scopes: the grant below would otherwise pass
    k.expires_at = Some(50);
    let observe = || Observed::At("MOVED".to_string());
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[Grant::Scope {
            kind: "thing",
            name: "nobody-holds-this",
        }],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::since(1, 2),
    };
    let refusal = validate_request(&ask).expect_err("four steps would refuse this");
    assert_eq!(
        refusal.step(),
        1,
        "identity is the first step, not the last"
    );
    assert_eq!(refusal.reason(), reason::IDENTITY_NOT_LIVE);
}

/// STEP 2 BEFORE STEP 3, and this is the leak the order exists to prevent: a caller with no grant
/// must learn that it is ungranted and NOTHING about what the upstream is currently offering.
///
/// Asserted on the fingerprint closure's OWN call counter rather than inferred from the refusal
/// word, because a refusal that happens to name the grant proves nothing about whether the artifact
/// was read on the way past.
///
/// RED: move the `capability` block above the grant loop and the counter reads 1.
#[test]
fn an_ungranted_caller_never_causes_the_artifact_to_be_read() {
    let (approval, sighting) = approved();
    let k = granting();
    let reads = Cell::new(0u32);
    let observe = || {
        reads.set(reads.get() + 1);
        Observed::At("d1".to_string())
    };
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[Grant::Scope {
            kind: "thing",
            name: "two",
        }],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::at_admission(7),
    };
    let refusal =
        validate_request(&ask).expect_err("the caller holds `thing:one`, not `thing:two`");
    assert_eq!(refusal.step(), 2);
    assert_eq!(refusal.reason(), reason::NOT_GRANTED);
    assert_eq!(
        reads.get(),
        0,
        "the artifact was fingerprinted on behalf of a caller with no grant to see it"
    );
}

/// AND THE CONTROL for the test above: on a granted caller the closure IS run. Without this, the
/// counter assertion would pass on a validator that never fingerprints anything at all.
#[test]
fn a_granted_caller_does_cause_the_artifact_to_be_read() {
    let (approval, sighting) = approved();
    let k = granting();
    let reads = Cell::new(0u32);
    let observe = || {
        reads.set(reads.get() + 1);
        Observed::At("d1".to_string())
    };
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[Grant::Scope {
            kind: "thing",
            name: "one",
        }],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::at_admission(7),
    };
    assert_eq!(validate_request(&ask), Ok(()));
    assert_eq!(reads.get(), 1);
}

/// `not_granted` and `egress_denied` are TWO WORDS, and they stay two: one is fixed on the caller's
/// key and the other on the target's standing list, so an operator handed one word for both is sent
/// to the wrong file half the time.
#[test]
fn the_two_grant_refusals_stay_distinguishable() {
    let (approval, sighting) = approved();
    let k = key(None);
    let allowed = vec!["someone-else".to_string()];
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[Grant::Egress {
            from: "me",
            allowed: &allowed,
        }],
        approval: &approval,
        sighting: &sighting,
        capability: None,
        generation: Generations::at_admission(7),
    };
    let refusal = validate_request(&ask).expect_err("not on the list");
    assert_eq!(refusal.step(), 2);
    assert_eq!(refusal.reason(), reason::EGRESS_DENIED);
    assert_ne!(reason::EGRESS_DENIED, reason::NOT_GRANTED);
    // AND NEITHER IS THE WORD FOR A CALL THAT WENT OUT AND BROKE. Reached through `audit::vocab`,
    // because that is where the vocabulary lives and this assertion is about the shared list rather
    // than about this module's view of it.
    assert_ne!(
        reason::NOT_GRANTED,
        crate::audit::vocab::REASON_UPSTREAM_FAILED
    );
}

/// AN EMPTY EGRESS LIST IS NOBODY, never everybody. The fail-closed reading, pinned here because the
/// other reading is the one somebody writes by accident.
#[test]
fn an_empty_egress_list_grants_nobody() {
    let (approval, sighting) = approved();
    let k = key(None);
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[Grant::Egress {
            from: "me",
            allowed: &[],
        }],
        approval: &approval,
        sighting: &sighting,
        capability: None,
        generation: Generations::at_admission(7),
    };
    assert_eq!(
        validate_request(&ask)
            .expect_err("empty is nobody")
            .reason(),
        reason::EGRESS_DENIED
    );
}

/// STEP 3, HALF ONE, BEFORE HALF TWO. A suspended registration serves nothing whatever a single
/// capability's fingerprint says, and the refusal names the SUSPENSION rather than the drift —
/// because "resume this registration" and "re-approve this capability" are two operator actions.
///
/// RED: drop the `state != Approved` block and this reports `artifact_drifted`, sending an operator
/// to work a changes queue on a registration they suspended by hand.
#[test]
fn the_registration_state_outranks_the_capability_fingerprint() {
    let (mut approval, sighting) = approved();
    approval.suspend("anomaly breaker: error rate");
    let k = key(None);
    let observe = || Observed::At("MOVED".to_string());
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::at_admission(7),
    };
    let refusal = validate_request(&ask).expect_err("suspended");
    assert_eq!(refusal.step(), 3);
    assert_eq!(refusal.reason(), reason::NOT_SERVING);
    assert!(matches!(
        refusal,
        Refusal::NotServing {
            state: TrustState::Suspended,
            reason: Some(_)
        }
    ));
}

/// THE RUG-PULL. The registration is `Approved` and the capability is offered at a fingerprint
/// nobody approved.
#[test]
fn a_moved_fingerprint_is_refused_and_named() {
    let (approval, sighting) = approved();
    let k = key(None);
    let observe = || Observed::At("MOVED".to_string());
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::at_admission(7),
    };
    let refusal = validate_request(&ask).expect_err("drifted");
    assert_eq!(refusal.step(), 3);
    assert_eq!(refusal.reason(), reason::ARTIFACT_DRIFTED);
    assert!(
        format!("{refusal}").contains("MOVED"),
        "the refusal must name what was observed, or an operator cannot compare it"
    );
}

/// A reader that can produce NO fingerprint says so in words for an operator, and those words reach
/// the refusal instead of being replaced by a generic one.
#[test]
fn a_reader_with_nothing_to_compare_refuses_in_its_own_words() {
    let (approval, sighting) = approved();
    let k = key(None);
    let observe = || Observed::Drifted("this capability is not in the last observed set");
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::at_admission(7),
    };
    let refusal = validate_request(&ask).expect_err("nothing to compare");
    assert_eq!(refusal.reason(), reason::ARTIFACT_DRIFTED);
    assert_eq!(refusal.step(), 3);
    assert!(matches!(refusal, Refusal::Unobservable { .. }));
    assert!(format!("{refusal}").contains("not in the last observed set"));
}

/// STEP 4 EXISTS, and it is LAST. Everything else about this request is fine; only the generation
/// moved.
///
/// RED: delete the generation comparison and this returns `Ok(())`.
#[test]
fn the_generation_is_the_last_step_and_it_exists() {
    let (approval, sighting) = approved();
    let k = granting();
    let observe = || Observed::At("d1".to_string());
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[Grant::Scope {
            kind: "thing",
            name: "one",
        }],
        approval: &approval,
        sighting: &sighting,
        capability: Some(Fingerprint {
            capability: "work",
            observe: &observe,
        }),
        generation: Generations::since(4, 5),
    };
    let refusal = validate_request(&ask).expect_err("the snapshot moved");
    assert_eq!(refusal.step(), 4);
    assert_eq!(refusal.reason(), reason::GENERATION_MOVED);
    assert_eq!(
        refusal,
        Refusal::GenerationMoved {
            admitted: 4,
            live: 5
        }
    );
}

/// AT ADMISSION the step runs and cannot fail: there is no earlier snapshot to have outlived. Pinned
/// so `at_admission` cannot quietly become a way of passing a mismatched pair.
#[test]
fn admission_compares_the_snapshot_against_itself() {
    let (approval, sighting) = approved();
    let k = key(None);
    let ask = Ask {
        principal: Some(&k),
        now: 100,
        grants: &[],
        approval: &approval,
        sighting: &sighting,
        capability: None,
        generation: Generations::at_admission(99),
    };
    assert_eq!(validate_request(&ask), Ok(()));
}

/// GOVERNANCE DISABLED is not a skipped gate. There is no principal, so there is no grant to narrow
/// — and every other step still runs, which is what this asserts: the same ask is refused on its
/// artifact.
#[test]
fn an_ungoverned_deployment_still_passes_through_every_other_step() {
    let (mut approval, sighting) = approved();
    approval.suspend("operator");
    let ask = Ask::<TwoPart> {
        principal: None,
        now: 100,
        grants: &[Grant::Scope {
            kind: "thing",
            name: "anything",
        }],
        approval: &approval,
        sighting: &sighting,
        capability: None,
        generation: Generations::at_admission(1),
    };
    let refusal = validate_request(&ask).expect_err("suspended, principal or no principal");
    assert_eq!(refusal.step(), 3);
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
        .still_permitted(Some(&gov), 1, 1_700_000_000)
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
        .still_permitted(Some(&gov), 1, 1_700_000_000)
        .is_ok());

    gov.update_key(&key.id, Some(false), None)
        .expect("the admin PATCH an operator makes")
        .expect("the key exists");

    assert_eq!(
        standing.still_permitted(Some(&gov), 1, 1_700_000_000),
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
        .still_permitted(Some(&gov), 1, 1_700_000_000)
        .is_ok());

    gov.delete_key(&key.id).expect("the admin DELETE");

    assert_eq!(
        standing.still_permitted(Some(&gov), 1, 1_700_000_000),
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
        .still_permitted(Some(&gov), 1, 1_700_000_000)
        .expect("a narrowed key is still a live key")
        .expect("a principal");
    assert!(resolved.scope_allowed("thing", "one"));
    assert!(
        !resolved.scope_allowed("thing", "two"),
        "the narrowing was not seen: the response is reading the copy taken at open"
    );
}

// ── THE CLASS: A DECISION MADE AT OPEN AND TRUSTED WHILE OPEN ───────────────────────────────────
//
// The two tests below are the class test for choke point J. They read the production source of
// every long-lived response in the tree and require each one to be in exactly one of two states:
// it RE-RESOLVES its principal, or it FREEZES it and says so beside the bound it is trading on.
//
// A source scan and not a behaviour test, deliberately: the hazard is a FIELD — a principal carried
// into a `'static` future — and a behaviour test can only cover the ways somebody thought to break
// it. The behavioural half is above, driven against a real registry.

/// `subscriptions/listen` RE-RESOLVES. Its code may not name `GovCtx` or `VirtualKey` at all, which
/// is the mechanical signature of the defect: the file used to carry `gov: ctx.gov.clone()`, and
/// that one field was the whole of it.
///
/// PROSE IS EXEMPT and must be — the module header explains the defect by naming both types, and
/// that explanation is the most useful thing in the file. Whole-line comments are stripped and only
/// the remaining code is judged, the same treatment the lifecycle's own plane-noun scan gets.
#[test]
fn the_long_lived_response_holds_no_principal_it_resolved_at_open() {
    let source = include_str!("../../mcp/subscribe.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in ["GovCtx", "gov.clone()"] {
        assert!(
            !code.contains(banned),
            "`{banned}` is back in the CODE of `subscriptions/listen`. A principal resolved at open \
             and carried into the stream is an identity believed for the whole life of the \
             response: hold a `trust::validate::Standing` and re-resolve per frame."
        );
    }
    assert!(
        code.contains("Standing::opened"),
        "the stream no longer opens a standing permission, so nothing re-resolves its principal"
    );
    assert!(
        code.contains("still_permitted"),
        "the stream opens a standing permission and never asks it anything"
    );
}

/// THE DETACHED TASK RUNNER FREEZES, AND THE FREEZE IS DISCLOSED BESIDE THE BOUND IT TRADES ON.
///
/// This is the second state the class permits, and permitting it is a judgement rather than an
/// oversight: the task path charges the caller's budget once at creation, so re-resolving the
/// principal mid-run would re-derive a grant against a settled charge. What is NOT permitted is
/// freezing silently — a reader of `Runner` must find the disclosure and the number in the same
/// place, because a bound nobody wrote down is a bound the next edit raises.
///
/// RED: delete the `TASK_TTL_MS` reference from the field's doc and this fails.
#[test]
fn the_detached_runner_discloses_its_frozen_principal_and_the_bound_it_trades_on() {
    let source = include_str!("../../mcp/tasks.rs");
    let field = source
        .split("pub(crate) struct Runner {")
        .nth(1)
        .expect("the runner still has a Runner struct")
        .split("pub(crate) authorised:")
        .next()
        .expect("the runner still carries an authorised leg");
    assert!(
        field.contains("TASK_TTL_MS"),
        "the frozen principal on `Runner` no longer names the bound that makes it survivable"
    );
    assert!(
        field.contains("BOUNDED"),
        "the freeze is no longer disclosed as a freeze"
    );
}
