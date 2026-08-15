// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/egress_auth/gate.rs` — THE ONE EGRESS GATE.
//!
//! Two jobs, and the second is the one that makes the unification worth doing:
//!
//! 1. **THE GATE'S OWN BEHAVIOUR.** Liveness, every requirement, the ORDER they are reported in, the
//!    frozen wildcard/empty-list semantics, and the witness that cannot be built without passing.
//!    Each of these ran RED against the gate with the corresponding check blinded; a gate whose
//!    checks are not individually watched is a gate that can lose one silently, which is exactly the
//!    defect that produced this unification (one plane checked key liveness, the other did not, and
//!    nobody decided that).
//!
//! 2. **THE SEAM.** `A THIRD PLANE COSTS A GRANT KIND AND NOTHING ELSE` is the acceptance test for
//!    this design, so this file declares a throwaway grant kind for a plane busbar does not have and
//!    shows it is GATED, REFUSED and AUDITED with NO gate, NO refusal enum, NO error type and NO
//!    `Display` written for it.
//!
//! It is deliberately UNLIKE both real planes: THREE requirements rather than two or one, scope kinds
//! from a vocabulary neither plane uses, an OWNED subject rather than a borrowed id or a reference to
//! an identity type, and a liveness rule. If the seam only fits things shaped like what already
//! exists, it is not a seam.

use super::*;

use crate::admin::audit::{AuditEntry, AuditInput, OUTCOME_REJECTED};
use crate::audit::{verify_chain, Chain};

// ══ THE THIRD PLANE ══════════════════════════════════════════════════════════════════════════════
//
// A grant kind for a plane that exists ONLY in this file. EVERYTHING BELOW IS THE WHOLE COST: an
// enum naming the checks, a subject, and one `impl EgressSubject`. If a future plane needs a gate, a
// refusal enum, an error type or a sentence of its own, the seam failed.

/// The three checks a "queue" plane's egress would require. THREE, because both real planes have
/// fewer, and a seam that only works for one or two requirements is a seam with a number baked in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueGrant {
    Broker,
    Topic,
    Region,
}

/// The subject: OWNED strings, unlike A2A's borrowed id and unlike MCP's reference to an existing
/// identity type. The gate must not care.
#[derive(Clone, Debug, PartialEq, Eq)]
struct QueueEgress {
    broker: String,
    topic: String,
    region: String,
}

impl EgressSubject for QueueEgress {
    type Grant = QueueGrant;
    const REQUIRE_LIVE_KEY: bool = true;

    fn grants_required(&self) -> Vec<Requirement<QueueGrant>> {
        vec![
            Requirement {
                grant: QueueGrant::Broker,
                scope_kind: "queue_broker",
                value: self.broker.clone(),
            },
            Requirement {
                grant: QueueGrant::Topic,
                scope_kind: "queue_topic",
                value: self.topic.clone(),
            },
            Requirement {
                grant: QueueGrant::Region,
                scope_kind: "queue_region",
                value: self.region.clone(),
            },
        ]
    }
}

fn a_queue() -> QueueEgress {
    QueueEgress {
        broker: "kafka-prod".to_string(),
        topic: "payments.settled".to_string(),
        region: "eu-west-1".to_string(),
    }
}

/// A key with an EXPLICIT scope list: what is not listed is not granted.
fn key_with(id: &str, scopes: &[(&str, &str)]) -> busbar_api::VirtualKey {
    let mut k = wildcard_key(id);
    k.allowed_scopes = Some(
        scopes
            .iter()
            .map(|(kind, value)| busbar_api::ScopeRef {
                kind: (*kind).to_string(),
                value: (*value).to_string(),
            })
            .collect(),
    );
    k
}

/// A key with NO scope restriction — `allowed_scopes: None`, the frozen 1.5.3 wildcard.
fn wildcard_key(id: &str) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: id.to_string(),
        generation_hash: String::new(),
        name: id.to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    }
}

/// A caller granted all three of the queue plane's scopes and nothing else.
fn a_fully_granted_caller() -> busbar_api::VirtualKey {
    key_with(
        "k-queue",
        &[
            ("queue_broker", "kafka-prod"),
            ("queue_topic", "payments.settled"),
            ("queue_region", "eu-west-1"),
        ],
    )
}

// ══ THE SEAM ═════════════════════════════════════════════════════════════════════════════════════

/// THE ACCEPTANCE TEST FOR THE WHOLE DESIGN: a plane that did not exist five minutes ago is gated,
/// refused, worded and audited, and the only thing written for it was the grant kind above.
#[test]
fn a_third_plane_costs_a_grant_kind_and_nothing_else() {
    // GATED. All three grants held: the witness is produced, and it carries the subject the check
    // was made against, so a mint reads its destination off the grant rather than beside it.
    let grant = authorise(&a_fully_granted_caller(), a_queue(), 0)
        .expect("a caller holding all three grants passes the gate");
    assert_eq!(grant.subject(), &a_queue());

    // REFUSED, once per requirement, IN THE DECLARED ORDER. Each caller below holds every grant
    // except one, so the arm reported can only be the missing one — a refusal battery where every
    // caller holds nothing would be equally green against a gate that refuses everything.
    for (missing, kind, value) in [
        (QueueGrant::Broker, "queue_broker", "kafka-prod"),
        (QueueGrant::Topic, "queue_topic", "payments.settled"),
        (QueueGrant::Region, "queue_region", "eu-west-1"),
    ] {
        let mut held = vec![
            ("queue_broker", "kafka-prod"),
            ("queue_topic", "payments.settled"),
            ("queue_region", "eu-west-1"),
        ];
        held.retain(|(k, _)| *k != kind);
        let refusal = authorise(&key_with("k-queue", &held), a_queue(), 0)
            .expect_err("a caller missing one of the three grants must be refused");
        assert_eq!(
            refusal,
            EgressRefusal::NoGrant {
                caller: "k-queue".to_string(),
                grant: missing,
                scope_kind: kind,
                value: value.to_string(),
            },
            "the refusal must name WHICH grant was missing, not merely that one was"
        );
        // WORDED, by core, with no `Display` written for this plane. The sentence names the caller
        // and the destination, because an unattributable denial is a denial nobody can act on.
        let rendered = refusal.to_string();
        assert!(
            rendered.contains("k-queue") && rendered.contains(value),
            "the refusal must name the caller and the destination: {rendered}"
        );
    }

    // AUDITED, in core's audit vocabulary, on core's hash chain, with no record type, no chain and
    // no resource spelling written for this plane. `nothing auditing wise should be mcp a2a or llm
    // specific` is the ruling; this is what it costs a new plane to comply with it: nothing.
    let refusal = authorise(&key_with("k-queue", &[]), a_queue(), 0).expect_err("no grants at all");
    assert_eq!(refusal.audit_resource(), "queue_broker:kafka-prod");
    assert_eq!(refusal.caller(), "k-queue");

    let mut chain: Chain<AuditEntry> = Chain::new();
    let records = vec![chain.append(
        "admin",
        AuditInput {
            ts: 1,
            action: "queue.egress".to_string(),
            resource: refusal.audit_resource(),
            outcome: OUTCOME_REJECTED.to_string(),
            principal: refusal.caller().to_string(),
        },
    )];
    assert_eq!(verify_chain(&records), Ok(()));
    assert_eq!(records[0].outcome, OUTCOME_REJECTED);
    assert_eq!(records[0].resource, "queue_broker:kafka-prod");
    assert_eq!(records[0].principal, "k-queue");

    // And the audited refusal is TAMPER-EVIDENT for the third plane exactly as it is for the three
    // real streams: rewriting who was refused breaks the chain.
    let mut forged = records;
    forged[0].principal = "someone-else".to_string();
    verify_chain(&forged).expect_err("an edited egress-refusal record must break the chain");
}

// ══ THE GATE'S OWN CHECKS ════════════════════════════════════════════════════════════════════════

/// LIVENESS IS FIRST, and it is checked at all. A key that may not authenticate may certainly not
/// cause a credential to be minted; a lease outliving the key that occasioned it is a hop nobody's
/// grant covers.
///
/// The principal here is a WILDCARD, so it would pass every grant if it were live: this isolates the
/// liveness half from the grant half, which a caller holding no scopes would not.
#[test]
fn a_key_that_is_not_live_is_refused_before_any_grant_is_looked_at() {
    for (what, mutate) in [
        (
            "disabled",
            Box::new(|k: &mut busbar_api::VirtualKey| k.enabled = false)
                as Box<dyn Fn(&mut busbar_api::VirtualKey)>,
        ),
        (
            "tombstoned",
            Box::new(|k: &mut busbar_api::VirtualKey| k.deleted_at = Some(1)),
        ),
        (
            "expired",
            Box::new(|k: &mut busbar_api::VirtualKey| k.expires_at = Some(500)),
        ),
    ] {
        let mut key = wildcard_key("k-dead");
        mutate(&mut key);
        assert_eq!(
            authorise(&key, a_queue(), 1_000).expect_err("a key that is not live obtains no grant"),
            EgressRefusal::KeyNotLive {
                caller: "k-dead".to_string()
            },
            "a {what} key must be refused as NOT LIVE, whatever it is granted"
        );
    }
}

/// EXPIRY IS AT THE INSTANT, not after it: a key whose `expires_at` equals `now` is expired. The
/// boundary is asserted from both sides so a `>` written where `>=` belongs is caught.
#[test]
fn a_key_expires_at_its_expiry_rather_than_after_it() {
    let mut key = wildcard_key("k-clock");
    key.expires_at = Some(1_000);
    assert!(
        authorise(&key, a_queue(), 999).is_ok(),
        "one millisecond before the expiry the key is still live"
    );
    assert_eq!(
        authorise(&key, a_queue(), 1_000).expect_err("at the expiry the key is expired"),
        EgressRefusal::KeyNotLive {
            caller: "k-clock".to_string()
        }
    );
}

/// A PLANE THAT DOES NOT REQUIRE LIVENESS DOES NOT GET IT IMPOSED. The MCP plane's egress has never
/// consulted key liveness, and the unification must not have quietly started: a gate that refuses
/// MORE after a refactor is still a behaviour change nobody asked for.
#[test]
fn a_plane_whose_policy_omits_liveness_does_not_have_it_imposed() {
    /// The same three requirements, with the liveness rule OFF.
    struct LivenessOff(QueueEgress);
    impl EgressSubject for LivenessOff {
        type Grant = QueueGrant;
        const REQUIRE_LIVE_KEY: bool = false;
        fn grants_required(&self) -> Vec<Requirement<QueueGrant>> {
            self.0.grants_required()
        }
    }

    let mut key = a_fully_granted_caller();
    key.enabled = false;
    key.deleted_at = Some(1);
    key.expires_at = Some(1);
    assert!(
        authorise(&key, LivenessOff(a_queue()), 1_000).is_ok(),
        "a plane that does not ask for the liveness check must not receive it"
    );
}

/// EVERY REQUIREMENT IS CHECKED, not just the first. A gate that stopped after one check would let a
/// coarse grant (`the broker`) silently become a fine one (`any topic on it`), which is the exact
/// widening the MCP plane's two-grant rule exists to prevent.
#[test]
fn holding_the_first_grant_alone_does_not_authorise_the_rest() {
    let refusal = authorise(
        &key_with("k-partial", &[("queue_broker", "kafka-prod")]),
        a_queue(),
        0,
    )
    .expect_err("the broker grant alone is not the topic grant");
    assert_eq!(
        refusal,
        EgressRefusal::NoGrant {
            caller: "k-partial".to_string(),
            grant: QueueGrant::Topic,
            scope_kind: "queue_topic",
            value: "payments.settled".to_string(),
        }
    );
}

/// THE ORDER IS THE CONTRACT. A caller holding none of the grants is told about the FIRST one, so an
/// operator diagnosing a denial is sent to the coarsest missing grant rather than to whichever check
/// happened to run last.
#[test]
fn a_caller_holding_nothing_is_refused_on_the_first_requirement() {
    let refusal =
        authorise(&key_with("k-none", &[]), a_queue(), 0).expect_err("no grants, no egress");
    assert!(
        matches!(
            refusal,
            EgressRefusal::NoGrant {
                grant: QueueGrant::Broker,
                ..
            }
        ),
        "the first declared requirement is the one reported: {refusal:?}"
    );
}

/// THE FROZEN 1.5.3 SEMANTICS, re-asserted at the one site where reading them the other way would be
/// an authority grant: an OMITTED scope list is a wildcard, an EXPLICIT EMPTY one is the empty set.
///
/// Pinned here rather than trusted from `busbar_api`, because this gate is where a "hardening" edit
/// that read a wildcard as the empty set would break every small deployment, and where an edit that
/// read the empty list as "all" would hand out every credential busbar holds.
#[test]
fn an_omitted_scope_list_is_a_wildcard_and_an_empty_one_is_the_empty_set() {
    assert!(
        authorise(&wildcard_key("k-root"), a_queue(), 0).is_ok(),
        "a wildcard principal is granted every scope of every kind"
    );
    assert!(
        authorise(&key_with("k-locked", &[]), a_queue(), 0).is_err(),
        "an explicit empty list grants nothing"
    );
}

/// A GRANT OF THE RIGHT VALUE UNDER THE WRONG KIND IS NO GRANT. `scope_allowed` is fail-closed
/// across kinds and the gate must not launder that: a caller granted the topic NAME under the broker
/// KIND holds nothing.
#[test]
fn a_grant_under_the_wrong_scope_kind_does_not_satisfy_a_requirement() {
    let key = key_with(
        "k-crosskind",
        &[
            ("queue_broker", "payments.settled"),
            ("queue_topic", "kafka-prod"),
            ("queue_region", "eu-west-1"),
        ],
    );
    assert!(
        matches!(
            authorise(&key, a_queue(), 0).expect_err("crossed kinds grant nothing"),
            EgressRefusal::NoGrant {
                grant: QueueGrant::Broker,
                ..
            }
        ),
        "the value must be looked up under the kind the requirement names"
    );
}
