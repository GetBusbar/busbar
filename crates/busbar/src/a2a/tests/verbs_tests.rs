// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/a2a/verbs.rs`.
//!
//! The three verbs the generic five-verb CRUD chassis models none of. Every test drives the REAL
//! `crate::trust` machine through the real verb; the only doubles are the two seams the delegating
//! side owns (the fetch and the verification), which is what lets a test stage the answers a real
//! network makes hard to produce on demand.

use super::*;
use crate::a2a::card;
use crate::a2a::pin::approve_registration;
use std::cell::RefCell;

const NOW_MS: u64 = 1_770_000_000_000;
const ISSUER: &str = "MCowBQYDK2VwAyEAtest-issuer-key-material-000000000000000=";

fn card_json(skill: &str, desc: &str) -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "skills": [{"id": skill, "name": skill, "description": desc}],
    })
}

fn a_pin(card: &serde_json::Value) -> CardPin {
    CardPin::JwsIssuerKey {
        issuer_key: ISSUER.to_string(),
        card_fingerprint: card::fingerprint(card).expect("fingerprintable"),
    }
}

/// A scripted card source: hands back a queued answer per call, so "the same host served a
/// different card the second time" is a two-element script rather than a network fixture.
struct ScriptedSource {
    answers: RefCell<Vec<Result<serde_json::Value, String>>>,
}

impl ScriptedSource {
    fn of(answers: Vec<Result<serde_json::Value, String>>) -> Self {
        Self {
            answers: RefCell::new(answers),
        }
    }
}

impl CardSource for ScriptedSource {
    fn fetch_card(&self, _agent_id: &str) -> Result<serde_json::Value, String> {
        let mut answers = self.answers.borrow_mut();
        assert!(
            !answers.is_empty(),
            "the source was called more times than the test scripted"
        );
        // The document is handed back AS RECEIVED. It is checked for readability on the way past —
        // an unparseable document is a contact failure — but what travels on is the raw value, not
        // the projection, because everything downstream hashes the received bytes.
        let v = answers.remove(0)?;
        card::parse(&v).map_err(|e| e.to_string())?;
        Ok(v)
    }
}

/// An observer that verifies (or refuses to) and produces the plane-neutral observation. Stands in
/// for the delegating side's JWS verification against the operator-pinned issuer key.
struct ScriptedObserver {
    /// The raw card the observation is derived from, and the pin it verified to. `Err` models a
    /// verification failure (unpinned card, wrong key, bad signature).
    outcome: RefCell<Vec<Result<serde_json::Value, String>>>,
}

impl ScriptedObserver {
    fn verifying(cards: Vec<serde_json::Value>) -> Self {
        Self {
            outcome: RefCell::new(cards.into_iter().map(Ok).collect()),
        }
    }
    fn refusing(reason: &str) -> Self {
        Self {
            outcome: RefCell::new(vec![Err(reason.to_string())]),
        }
    }
}

impl CardObserver for ScriptedObserver {
    fn observe(&self, _card: &serde_json::Value) -> Result<Observation<CardPin>, String> {
        let mut outcome = self.outcome.borrow_mut();
        assert!(
            !outcome.is_empty(),
            "the observer was called more times than the test scripted"
        );
        let raw = outcome.remove(0)?;
        let pin = a_pin(&raw);
        card::observation(&raw, Some(pin)).map_err(|e| e.to_string())
    }
}

// ── connect ──────────────────────────────────────────────────────────────────────────────────

/// THE PROPERTY THIS VERB EXISTS FOR: a preview never grants. Asserted on the happy path, because
/// the happy path is the only one anybody would be tempted to shortcut.
#[test]
fn connect_previews_a_perfectly_good_card_and_still_grants_nothing() {
    let raw = card_json("plan", "makes plans");
    let approval = Approval::<CardPin>::registered();
    let preview = connect(
        "planner",
        &approval,
        &CardProbe {
            source: &ScriptedSource::of(vec![Ok(raw.clone())]),
            observer: &ScriptedObserver::verifying(vec![raw.clone()]),
        },
    );
    assert!(
        preview.grants_nothing(),
        "a preview must never leave a registration able to serve"
    );
    assert_eq!(preview.state, TrustState::Pending);
    assert_eq!(
        preview.fingerprint,
        Some(card::fingerprint(&raw).unwrap()),
        "the fingerprint the operator is being asked to approve is surfaced, not buried"
    );
    assert!(matches!(preview.sighting, Sighting::Seen(_)));
    // The approval itself is UNTOUCHED: nothing here writes.
    assert!(approval.pin().is_none(), "connect locked no pin");
    assert!(!approval.serves("plan", "anything"), "and nothing serves");
}

/// EVEN AN ALREADY-APPROVED registration previews as `Pending`. Returning `Approved` from a preview
/// invites a caller to treat the preview as the grant, which is the exact confusion the verb exists
/// to prevent.
#[test]
fn connect_never_reports_approved_even_when_the_card_matches_a_locked_pin() {
    let raw = card_json("plan", "makes plans");
    let mut approval = Approval::<CardPin>::registered();
    let observer = ScriptedObserver::verifying(vec![raw.clone(), raw.clone()]);
    let sighting = Sighting::Seen(card::observation(&raw, Some(a_pin(&raw))).unwrap());
    approve_registration(&mut approval, &sighting, None).expect("operator approves");
    assert_eq!(
        approval.state(&sighting),
        TrustState::Approved,
        "the registration really is approved"
    );

    let preview = connect(
        "planner",
        &approval,
        &CardProbe {
            source: &ScriptedSource::of(vec![Ok(raw.clone())]),
            observer: &observer,
        },
    );
    assert_eq!(preview.state, TrustState::Pending);
    assert!(preview.grants_nothing());
    assert!(
        preview.drift.is_empty(),
        "and it correctly reports no drift against what is approved"
    );
}

/// A CONTACT FAILURE is a sighting, not an absence. Treating it as "nothing observed" is the
/// cheapest possible way for an upstream to avoid being checked.
#[test]
fn connect_records_a_contact_failure_as_a_sighting_that_can_never_serve() {
    let approval = Approval::<CardPin>::registered();
    let preview = connect(
        "planner",
        &approval,
        &CardProbe {
            source: &ScriptedSource::of(vec![Err("connection refused".to_string())]),
            observer: &ScriptedObserver::verifying(vec![]),
        },
    );
    assert!(
        matches!(preview.sighting, Sighting::Failed(ref e) if e.contains("connection refused"))
    );
    assert_eq!(preview.state, TrustState::Error);
    assert!(preview.grants_nothing());
    assert_eq!(
        preview.fingerprint, None,
        "nothing was verified, so nothing is offered to approve"
    );
}

/// A VERIFICATION failure lands in the same arm as a contact failure, and must: neither may ever
/// read as "unchanged".
#[test]
fn connect_treats_a_failed_verification_exactly_as_it_treats_a_failed_contact() {
    let raw = card_json("plan", "makes plans");
    let approval = Approval::<CardPin>::registered();
    let preview = connect(
        "planner",
        &approval,
        &CardProbe {
            source: &ScriptedSource::of(vec![Ok(raw)]),
            observer: &ScriptedObserver::refusing("card is signed by the wrong issuer key"),
        },
    );
    assert!(matches!(preview.sighting, Sighting::Failed(_)));
    assert_eq!(preview.state, TrustState::Error);
    assert!(preview.grants_nothing());
}

/// RE-CONNECTING an approved registration whose card has MOVED reports the drift, so the operator
/// sees what changed instead of being asked to re-approve a blank.
#[test]
fn connect_reports_what_moved_when_an_approved_card_has_changed() {
    let original = card_json("plan", "makes plans");
    let changed = card_json("plan", "makes plans AND exfiltrates them");
    let mut approval = Approval::<CardPin>::registered();
    let first = Sighting::Seen(card::observation(&original, Some(a_pin(&original))).unwrap());
    approve_registration(&mut approval, &first, None).unwrap();

    let preview = connect(
        "planner",
        &approval,
        &CardProbe {
            source: &ScriptedSource::of(vec![Ok(changed.clone())]),
            observer: &ScriptedObserver::verifying(vec![changed]),
        },
    );
    assert!(preview.drift.pin_changed, "the card fingerprint moved");
    assert_eq!(
        preview.drift.changed,
        vec!["plan".to_string()],
        "and the skill's digest with it"
    );
    assert_eq!(preview.state, TrustState::Quarantined);
    assert!(preview.grants_nothing());
}

// ── sync ─────────────────────────────────────────────────────────────────────────────────────

/// `sync` OUTRANKS THE TIMER: it runs even when the freshness window has not elapsed.
#[test]
fn sync_runs_even_when_the_ttl_says_it_is_not_due() {
    let raw = card_json("plan", "makes plans");
    let approval = Approval::<CardPin>::registered();
    let mut ledger = Ledger {
        last_checked_ms: Some(NOW_MS),
        ..Ledger::default()
    };
    let policy = Policy {
        ttl_ms: 6 * 3_600_000,
        recovery_backoff_ms: 60_000,
    };
    // The timer says NO...
    assert_eq!(
        crate::a2a::reverify::due(&ledger, &policy, NOW_MS + 1, false),
        Due::No
    );
    // ...and the operator's sync happens anyway.
    let out = sync(
        "planner",
        &approval,
        &Sighting::Never,
        &mut ledger,
        &policy,
        NOW_MS + 1,
        &CardProbe {
            source: &ScriptedSource::of(vec![Ok(raw.clone())]),
            observer: &ScriptedObserver::verifying(vec![raw]),
        },
    );
    assert_eq!(out.due, Due::OperatorSync);
    assert_eq!(
        ledger.last_checked_ms,
        Some(NOW_MS + 1),
        "the ledger is stamped by the operator-driven check too"
    );
}

/// DEMOTION IS NEVER RATE-LIMITED. The first drift demotes immediately even when the last drift was
/// a moment ago — flapping recently must never buy a hostile upstream a free window.
#[test]
fn sync_demotes_on_drift_immediately_and_counts_every_observation() {
    let original = card_json("plan", "makes plans");
    let changed = card_json("plan", "and now something else");
    let mut approval = Approval::<CardPin>::registered();
    let first = Sighting::Seen(card::observation(&original, Some(a_pin(&original))).unwrap());
    approve_registration(&mut approval, &first, None).unwrap();

    let policy = Policy {
        ttl_ms: 1_000,
        recovery_backoff_ms: 3_600_000,
    };
    let mut ledger = Ledger {
        last_checked_ms: Some(NOW_MS),
        last_drift_ms: Some(NOW_MS),
        drift_observations: 1,
    };
    let out = sync(
        "planner",
        &approval,
        &first,
        &mut ledger,
        &policy,
        NOW_MS + 10,
        &CardProbe {
            source: &ScriptedSource::of(vec![Ok(changed.clone())]),
            observer: &ScriptedObserver::verifying(vec![changed]),
        },
    );
    assert!(out.drift_observed);
    assert!(!out.recovery_held, "a demotion is never held");
    assert_eq!(out.state, TrustState::Quarantined);
    assert_eq!(ledger.drift_observations, 2, "every observation is counted");
}

/// RECOVERY is the direction that is held. A clean answer inside the backoff is DISBELIEVED, and the
/// hold is reported so an operator can tell "still broken" from "claims to be fine, too soon to say".
#[test]
fn sync_holds_a_recovery_inside_the_backoff_and_says_it_did() {
    let original = card_json("plan", "makes plans");
    let mut approval = Approval::<CardPin>::registered();
    let good = Sighting::Seen(card::observation(&original, Some(a_pin(&original))).unwrap());
    approve_registration(&mut approval, &good, None).unwrap();

    let drifted = card_json("plan", "drifted");
    let drifted_sighting =
        Sighting::Seen(card::observation(&drifted, Some(a_pin(&drifted))).unwrap());

    let policy = Policy {
        ttl_ms: 1_000,
        recovery_backoff_ms: 3_600_000,
    };
    let mut ledger = Ledger {
        last_checked_ms: Some(NOW_MS),
        last_drift_ms: Some(NOW_MS),
        drift_observations: 1,
    };
    let out = sync(
        "planner",
        &approval,
        &drifted_sighting,
        &mut ledger,
        &policy,
        NOW_MS + 60_000,
        &CardProbe {
            source: &ScriptedSource::of(vec![Ok(original.clone())]),
            observer: &ScriptedObserver::verifying(vec![original]),
        },
    );
    assert!(out.recovery_held, "the clean answer is not believed yet");
    assert!(!out.drift_observed);
    assert_eq!(
        out.recorded, drifted_sighting,
        "what stays RECORDED is the drifted observation"
    );
    assert_eq!(out.state, TrustState::Quarantined);
}

/// A FAILED CONTACT during a sync never clears the drift clock. An upstream that could age its own
/// quarantine out by refusing connections would have the cheapest possible escape.
#[test]
fn a_failed_sync_is_an_error_and_never_a_recovery() {
    let approval = Approval::<CardPin>::registered();
    let policy = Policy {
        ttl_ms: 1_000,
        recovery_backoff_ms: 1_000,
    };
    let mut ledger = Ledger {
        last_checked_ms: Some(NOW_MS),
        last_drift_ms: Some(NOW_MS),
        drift_observations: 1,
    };
    let out = sync(
        "planner",
        &approval,
        &Sighting::Never,
        &mut ledger,
        &policy,
        NOW_MS + 10_000,
        &CardProbe {
            source: &ScriptedSource::of(vec![Err("TLS handshake failed".to_string())]),
            observer: &ScriptedObserver::verifying(vec![]),
        },
    );
    assert_eq!(out.state, TrustState::Error);
    assert_eq!(
        ledger.last_drift_ms,
        Some(NOW_MS),
        "the drift clock was NOT cleared by a failure"
    );
}

// ── suspend / resume ─────────────────────────────────────────────────────────────────────────

/// A SUSPENSION MUST CARRY A REASON. A breaker whose trips are unexplainable gets its thresholds
/// raised into uselessness, which is the failure mode the whole control is defending against.
#[test]
fn a_suspension_without_a_real_reason_is_refused() {
    for bad in ["", "   ", "x", "bad", "oops"] {
        let mut approval = Approval::<CardPin>::registered();
        assert_eq!(
            operator_suspend(&mut approval, bad, "alice"),
            Err(SuspendError::ReasonMissing),
            "`{bad}` names nothing"
        );
        assert!(
            approval.suspension().is_none(),
            "and a refused suspension changes nothing"
        );
    }
}

/// SUSPENSION IS INDEPENDENT OF TRUST STATE. The failure it defends against is a
/// legitimately-approved agent with a byte-identical card that simply starts behaving badly, which
/// triggers nothing in the card-identity machinery by construction.
#[test]
fn an_operator_can_suspend_a_perfectly_trusted_agent_and_the_reason_names_who_did_it() {
    let raw = card_json("plan", "makes plans");
    let mut approval = Approval::<CardPin>::registered();
    let sighting = Sighting::Seen(card::observation(&raw, Some(a_pin(&raw))).unwrap());
    approve_registration(&mut approval, &sighting, None).unwrap();
    assert_eq!(approval.state(&sighting), TrustState::Approved);
    let digest = card::skill_digests(&raw).unwrap()["plan"].clone();
    assert!(
        approval.serves("plan", &digest),
        "it serves before the suspension"
    );

    let stamped = operator_suspend(&mut approval, "vendor breach notice CVE-2026-1", "alice")
        .expect("a real reason is accepted");
    assert!(stamped.contains("vendor breach notice"));
    assert!(
        stamped.contains("alice"),
        "the reason names WHO, or nobody can follow it up"
    );
    assert_eq!(approval.suspension(), Some(stamped.as_str()));
    assert_eq!(
        approval.state(&sighting),
        TrustState::Suspended,
        "suspension outranks a perfectly valid pin"
    );
    assert!(
        !approval.serves("plan", &digest),
        "and it is refused at dispatch regardless of how trusted it was"
    );

    // Resume restores exactly what the machine still holds, and nothing more.
    operator_resume(&mut approval);
    assert_eq!(approval.suspension(), None);
    assert_eq!(approval.state(&sighting), TrustState::Approved);
}

/// RESUMING cannot make an UNVERIFIED agent serve. That is why resume needs no ceremony: the
/// evidence that matters is the trust state the machine still holds.
#[test]
fn resuming_an_unpinned_registration_still_serves_nothing() {
    let mut approval = Approval::<CardPin>::registered();
    operator_suspend(&mut approval, "out-of-band intelligence", "alice").unwrap();
    operator_resume(&mut approval);
    assert_eq!(approval.state(&Sighting::Never), TrustState::Pending);
    assert!(!approval.serves("plan", "anything"));
}
