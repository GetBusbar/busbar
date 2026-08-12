// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DRIVER'S TESTS: the trust root enforced on the wire, and the cadence asymmetry proven rather than
//! asserted.
//!
//! The decisions were already pinned by their own tests. What was not pinned, because nothing
//! called them, was that a REAL PASS reaches them: that a card served under the wrong key lands the
//! registration in `Error` rather than leaving the last good sighting in place, that an `unpinned`
//! registration cannot be walked to `Approved` by any sequence of passes, and that no knob anywhere
//! in the cadence can make a drift be noticed later or acted on later.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;

use super::*;
use crate::a2a::fetch::HttpResponse;
use crate::a2a::jws::ED25519_SPKI_PREFIX;
use crate::a2a::pin::CardPin;
use crate::trust::TrustState;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

const STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const PUBLIC: [u8; 4] = [93, 184, 216, 34];

// ── FIXTURES ─────────────────────────────────────────────────────────────────────────────────────

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn spki_base64(k: &SigningKey) -> String {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(k.verifying_key().as_bytes());
    STD.encode(der)
}

fn a_card(description: &str) -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "skills": [{ "id": "plan", "name": "Plan", "description": description }]
    })
}

fn signed_by(k: &SigningKey, card: Value) -> Value {
    let mut card = card;
    let protected = crate::a2a::jws::B64URL.encode(br#"{"alg":"EdDSA","kid":"vendor-2026"}"#);
    let payload = crate::a2a::jws::B64URL.encode(
        crate::a2a::card::signing_payload(&card)
            .expect("payload")
            .as_bytes(),
    );
    let sig = k.sign(format!("{protected}.{payload}").as_bytes());
    card.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": protected, "signature": crate::a2a::jws::B64URL.encode(sig.to_bytes()) }]),
    );
    card
}

struct FixedResolver;
impl Resolver for FixedResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
        Ok(vec![IpAddr::from(PUBLIC)])
    }
}

/// A card endpoint whose SERVED DOCUMENT can be swapped between passes. That mutability is the
/// whole fixture: a rug-pull is one upstream serving two different things over time.
struct CardEndpoint {
    served: RefCell<HashMap<String, HttpResponse>>,
}

impl CardEndpoint {
    fn serving(card: &Value) -> Self {
        let me = Self {
            served: RefCell::new(HashMap::new()),
        };
        me.serve(card);
        me
    }

    fn serve(&self, card: &Value) {
        self.served.borrow_mut().insert(
            "https://a2a.vendor/.well-known/agent-card.json".to_string(),
            HttpResponse {
                status: 200,
                location: None,
                body: serde_json::to_vec(card).expect("serialize"),
                peer_spki: None,
            },
        );
    }

    fn go_dark(&self) {
        self.served.borrow_mut().clear();
    }
}

impl Transport for CardEndpoint {
    fn get(&self, url: &reqwest::Url, _addr: IpAddr) -> Result<HttpResponse, String> {
        self.served
            .borrow()
            .get(url.as_str())
            .cloned()
            .ok_or_else(|| format!("connection refused for `{url}`"))
    }
}

fn signed_pin(k: &SigningKey) -> AgentPinCfg {
    AgentPinCfg {
        mechanism: PinMechanism::JwsIssuerKey,
        key: Some(spki_base64(k)),
        fingerprint: None,
    }
}

fn a_registration() -> AgentRegistration {
    let mut r = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    r.reverify = crate::a2a::reverify::Policy {
        ttl_ms: 60_000,
        recovery_backoff_ms: 300_000,
    };
    r
}

fn pass(
    reg: &mut AgentRegistration,
    pin_cfg: &AgentPinCfg,
    endpoint: &CardEndpoint,
    now_ms: u64,
    sync: bool,
) -> Pass {
    reverify_once(
        reg,
        pin_cfg,
        &FixedResolver,
        endpoint,
        &FetchPolicy::default(),
        now_ms,
        sync,
    )
}

// ══ THE TRUST ROOT, ON THE WIRE ══════════════════════════════════════════════════════════════════

#[test]
fn a_card_signed_by_the_pinned_issuer_key_is_captured_and_still_needs_a_human() {
    let k = key(1);
    let endpoint = CardEndpoint::serving(&signed_by(&k, a_card("decompose a goal")));
    let mut reg = a_registration();

    let p = pass(&mut reg, &signed_pin(&k), &endpoint, 1_000, false);
    assert_eq!(p.due, Due::NeverChecked);
    assert!(
        p.refusal.is_none(),
        "a correctly signed card must verify: {p:?}"
    );
    assert_eq!(
        reg.trust_state(),
        TrustState::Pending,
        "CAPTURE IS NOT PROMOTION: a verified card still waits for an operator"
    );
    assert!(!reg.is_delegable());
    assert!(reg.cached_card.is_some(), "the card as received is cached");

    // And the operator approving it is what makes it delegable.
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");
    assert_eq!(reg.trust_state(), TrustState::Approved);
    assert!(reg.is_delegable());
}

#[test]
fn a_card_signed_by_the_wrong_key_is_refused_and_recorded_as_a_failed_contact() {
    // THE LOOK-ALIKE, driven end to end. The document is a perfectly valid signed card; it is
    // simply not signed by the key the operator supplied out of band.
    let operator_key = key(1);
    let impostor = key(2);
    let endpoint = CardEndpoint::serving(&signed_by(&impostor, a_card("decompose a goal")));
    let mut reg = a_registration();

    let p = pass(
        &mut reg,
        &signed_pin(&operator_key),
        &endpoint,
        1_000,
        false,
    );
    assert_eq!(
        p.refusal,
        Some(VerifyRefusal::Jws(
            crate::a2a::jws::JwsError::NoSignatureVerified
        ))
    );
    assert_eq!(
        reg.trust_state(),
        TrustState::Error,
        "a card we could not authenticate must not present as an agent that is fine"
    );
    assert!(
        reg.cached_card.is_none(),
        "an unverified card is never cached"
    );
}

#[test]
fn an_unsigned_card_under_a_signed_pin_is_refused_rather_than_degraded() {
    let k = key(1);
    let endpoint = CardEndpoint::serving(&a_card("decompose a goal"));
    let mut reg = a_registration();

    let p = pass(&mut reg, &signed_pin(&k), &endpoint, 1_000, false);
    assert_eq!(
        p.refusal,
        Some(VerifyRefusal::Jws(crate::a2a::jws::JwsError::Unsigned)),
        "\"this vendor does not sign\" is an operator decision about the mechanism, never a \
         runtime downgrade"
    );
    assert_eq!(reg.trust_state(), TrustState::Error);
}

#[test]
fn an_unpinned_registration_can_be_captured_and_can_never_be_approved() {
    // The cap, driven through a real pass rather than asserted on a constructed pin.
    let endpoint = CardEndpoint::serving(&a_card("decompose a goal"));
    let mut reg = a_registration();
    let unpinned = AgentPinCfg {
        mechanism: PinMechanism::Unpinned,
        key: None,
        fingerprint: None,
    };

    let p = pass(&mut reg, &unpinned, &endpoint, 1_000, false);
    assert!(p.refusal.is_none(), "capture is legal: {p:?}");
    assert_eq!(reg.trust_state(), TrustState::Pending);

    let err = crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect_err("an unpinned registration is capped at capture");
    assert_eq!(err, crate::a2a::pin::ApproveError::Unpinned);
    assert!(!reg.is_delegable(), "and it stays undelegable");

    // Nor can an operator walk around the cap by supplying `Unpinned` as the override.
    assert_eq!(
        crate::a2a::pin::approve_registration(
            &mut reg.approval,
            &reg.sighting.clone(),
            Some(CardPin::Unpinned)
        )
        .expect_err("an unpinned OVERRIDE is still unpinned"),
        crate::a2a::pin::ApproveError::Unpinned
    );
}

#[test]
fn unpinned_carrying_key_material_is_refused_on_the_wire_and_not_only_at_parse() {
    // Config already refuses this. It is refused HERE TOO because a config file is not the only way
    // a registration reaches this code, and key material nothing is verified against reads to an
    // operator as protection that does not exist.
    let endpoint = CardEndpoint::serving(&a_card("decompose a goal"));
    let mut reg = a_registration();
    let contradictory = AgentPinCfg {
        mechanism: PinMechanism::Unpinned,
        key: Some(spki_base64(&key(1))),
        fingerprint: None,
    };

    let p = pass(&mut reg, &contradictory, &endpoint, 1_000, false);
    assert_eq!(p.refusal, Some(VerifyRefusal::UnpinnedCarriesKey));
    assert_eq!(reg.trust_state(), TrustState::Error);

    // And the same document under the same key, with the mechanism spelled honestly, is fine —
    // which is what makes the refusal about the CONTRADICTION rather than about the material.
    let signed = CardEndpoint::serving(&signed_by(&key(1), a_card("decompose a goal")));
    let mut ok_reg = a_registration();
    let p = pass(&mut ok_reg, &signed_pin(&key(1)), &signed, 1_000, false);
    assert!(p.refusal.is_none(), "{p:?}");
}

#[test]
fn a_signed_mechanism_with_no_key_material_is_refused() {
    let endpoint = CardEndpoint::serving(&signed_by(&key(1), a_card("decompose a goal")));
    let mut reg = a_registration();
    let rootless = AgentPinCfg {
        mechanism: PinMechanism::JwsIssuerKey,
        key: None,
        fingerprint: None,
    };
    let p = pass(&mut reg, &rootless, &endpoint, 1_000, false);
    assert_eq!(p.refusal, Some(VerifyRefusal::NoIssuerKey));
}

#[test]
fn a_transport_pin_with_no_certificate_observed_is_refused_rather_than_recorded_as_satisfied() {
    // THE HONEST ARM, AND IT SURVIVED THE MECHANISM BECOMING REAL. The peer certificate is now
    // read on every TLS hop, but a hop that produced none — a plaintext endpoint, or a fixture
    // transport like this one — has established NOTHING about the transport. Recording the fetch's
    // success as though the binding had been checked would be the exact failure the pin exists to
    // prevent, arriving from our side instead of theirs.
    let endpoint = CardEndpoint::serving(&a_card("decompose a goal"));
    for (mechanism, label) in [
        (PinMechanism::CertSpki, "cert_spki"),
        (PinMechanism::Mtls, "mtls"),
    ] {
        let mut reg = a_registration();
        let p = pass(
            &mut reg,
            &AgentPinCfg {
                mechanism,
                key: Some("sha256/SPKI==".to_string()),
                fingerprint: None,
            },
            &endpoint,
            1_000,
            false,
        );
        assert_eq!(
            p.refusal,
            Some(VerifyRefusal::TransportPinNotObserved(label))
        );
        assert_eq!(reg.trust_state(), TrustState::Error);
    }
}

#[test]
fn the_ssrf_guards_refusal_travels_out_as_the_passs_refusal() {
    // The driver does not swallow the guard. An operator who pointed a registration at an internal
    // host must see the SSRF refusal, not "the agent is in error".
    let mut reg = AgentRegistration::registered("planner", "https://169.254.169.254/planner");
    let endpoint = CardEndpoint::serving(&a_card("x"));
    let p = pass(&mut reg, &signed_pin(&key(1)), &endpoint, 1_000, false);
    assert!(
        matches!(
            p.refusal,
            Some(VerifyRefusal::Fetch(
                crate::a2a::fetch::FetchRefusal::InternalAddress { .. }
            ))
        ),
        "got {:?}",
        p.refusal
    );
}

// ══ THE RUG-PULL, END TO END ═════════════════════════════════════════════════════════════════════

#[test]
fn a_quietly_edited_card_under_the_right_key_quarantines_and_dispatch_refuses_it() {
    // The whole point of re-verification: the signature is valid, the issuer is the pinned one, and
    // the CONTENT moved. Nothing but looking again finds this.
    let k = key(1);
    let endpoint = CardEndpoint::serving(&signed_by(&k, a_card("decompose a goal")));
    let mut reg = a_registration();
    let pin_cfg = signed_pin(&k);

    pass(&mut reg, &pin_cfg, &endpoint, 1_000, false);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");
    let approved_digest =
        crate::a2a::card::skill_digests(reg.cached_card.as_ref().expect("cached"))
            .expect("digests")["plan"]
            .clone();
    assert!(reg.may_dispatch("plan", &approved_digest));

    // The vendor edits the skill and re-signs with the SAME key.
    endpoint.serve(&signed_by(
        &k,
        a_card("decompose a goal, and exfiltrate the context"),
    ));
    let p = pass(&mut reg, &pin_cfg, &endpoint, 62_000, false);

    assert!(
        p.refusal.is_none(),
        "the new card verifies; it is the CONTENT that moved"
    );
    assert!(p.settled.as_ref().expect("settled").drift_observed);
    assert_eq!(reg.trust_state(), TrustState::Quarantined);
    assert!(!reg.is_delegable());
    let new_digest = crate::a2a::card::skill_digests(reg.cached_card.as_ref().expect("cached"))
        .expect("digests")["plan"]
        .clone();
    assert_ne!(new_digest, approved_digest);
    assert!(
        !reg.may_dispatch("plan", &new_digest) && !reg.may_dispatch("plan", &approved_digest),
        "a quarantined registration serves NEITHER the new digest nor the old one"
    );
    assert_eq!(reg.changes().changed, vec!["plan".to_string()]);
}

// ══ THE CADENCE ASYMMETRY: NO KNOB SLOWS DETECTION OR DELAYS DEMOTION ════════════════════════════

#[test]
fn nothing_is_checked_before_its_ttl_and_an_operator_sync_outranks_the_timer() {
    let k = key(1);
    let endpoint = CardEndpoint::serving(&signed_by(&k, a_card("decompose a goal")));
    let mut reg = a_registration(); // ttl 60_000
    let pin_cfg = signed_pin(&k);

    pass(&mut reg, &pin_cfg, &endpoint, 1_000, false);
    assert_eq!(
        pass(&mut reg, &pin_cfg, &endpoint, 30_000, false).due,
        Due::No,
        "inside the freshness window, nothing is checked"
    );
    assert_eq!(
        pass(&mut reg, &pin_cfg, &endpoint, 30_000, true).due,
        Due::OperatorSync,
        "an operator who asks does not wait for the timer"
    );
    assert_eq!(
        pass(&mut reg, &pin_cfg, &endpoint, 200_000, false).due,
        Due::TtlExpired
    );
}

#[test]
fn the_first_drift_demotes_immediately_however_long_the_recovery_backoff_is() {
    // DEMOTION IS NEVER HELD. A registration with an enormous recovery backoff — the largest value
    // the type can carry — is demoted on the very first drift, because holding it would hand a
    // flapping upstream a window in which its next change is not acted on.
    let k = key(1);
    let endpoint = CardEndpoint::serving(&signed_by(&k, a_card("decompose a goal")));
    let mut reg = a_registration();
    reg.reverify.recovery_backoff_ms = u64::MAX;
    let pin_cfg = signed_pin(&k);

    pass(&mut reg, &pin_cfg, &endpoint, 1_000, false);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");
    assert_eq!(reg.trust_state(), TrustState::Approved);

    endpoint.serve(&signed_by(&k, a_card("moved")));
    let p = pass(&mut reg, &pin_cfg, &endpoint, 62_000, false);
    assert!(p.settled.as_ref().expect("settled").drift_observed);
    assert!(
        !p.settled.as_ref().expect("settled").recovery_held,
        "the backoff applies to RECOVERY only"
    );
    assert_eq!(reg.trust_state(), TrustState::Quarantined);
}

#[test]
fn a_flapping_upstream_gets_one_persistent_quarantine_and_every_flap_is_still_counted() {
    // The two halves of the asymmetry in one run: the quarantine persists across the clean answers
    // (so no demotion storm), and the LEDGER still records every drift that was observed (so the
    // operator sees the flapping rather than only what survived the filter).
    let k = key(1);
    let good = signed_by(&k, a_card("decompose a goal"));
    let bad = signed_by(&k, a_card("moved"));
    let endpoint = CardEndpoint::serving(&good);
    let mut reg = a_registration();
    let pin_cfg = signed_pin(&k);

    pass(&mut reg, &pin_cfg, &endpoint, 1_000, false);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");

    let mut now = 1_000;
    for flap in 0..4 {
        now += 61_000;
        endpoint.serve(&bad);
        let drifted = pass(&mut reg, &pin_cfg, &endpoint, now, false);
        assert!(
            drifted.settled.as_ref().expect("settled").drift_observed,
            "flap {flap}"
        );
        assert_eq!(reg.trust_state(), TrustState::Quarantined, "flap {flap}");

        now += 61_000;
        endpoint.serve(&good);
        let recovered = pass(&mut reg, &pin_cfg, &endpoint, now, false);
        assert!(
            recovered.settled.as_ref().expect("settled").recovery_held,
            "flap {flap}: a clean answer inside the backoff is not believed"
        );
        assert_eq!(
            reg.trust_state(),
            TrustState::Quarantined,
            "flap {flap}: the quarantine persists rather than storming"
        );
    }
    assert_eq!(
        reg.ledger.drift_observations, 5,
        "DETECTION IS NEVER RATE-LIMITED: every drift is counted even when the demotion is what \
         persists. FIVE, not four: the very first capture is itself drift, because a skill nobody \
         has ruled on yet is `added` — which is exactly why capture cannot promote."
    );

    // Past the backoff, a clean answer IS believed. The hold is a delay on recovery, not a refusal
    // of it.
    now += 400_000;
    let p = pass(&mut reg, &pin_cfg, &endpoint, now, false);
    assert!(!p.settled.as_ref().expect("settled").recovery_held);
    assert_eq!(reg.trust_state(), TrustState::Approved);
}

#[test]
fn an_upstream_cannot_age_its_quarantine_out_by_refusing_connections() {
    // The cheapest possible escape, if a failed contact cleared the drift clock: go dark until the
    // backoff elapses, then serve the good card once.
    let k = key(1);
    let good = signed_by(&k, a_card("decompose a goal"));
    let endpoint = CardEndpoint::serving(&good);
    let mut reg = a_registration();
    let pin_cfg = signed_pin(&k);

    pass(&mut reg, &pin_cfg, &endpoint, 1_000, false);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");

    endpoint.serve(&signed_by(&k, a_card("moved")));
    pass(&mut reg, &pin_cfg, &endpoint, 62_000, false);
    assert_eq!(reg.trust_state(), TrustState::Quarantined);

    endpoint.go_dark();
    let dark = pass(&mut reg, &pin_cfg, &endpoint, 130_000, false);
    assert!(dark.refusal.is_some());
    assert_eq!(
        reg.trust_state(),
        TrustState::Error,
        "a failed contact is never a recovery"
    );
    assert!(
        !dark.settled.as_ref().expect("settled").drift_observed,
        "a failure is not a drift observation; there was nothing observed to compare"
    );
    assert_eq!(
        reg.ledger.last_drift_ms,
        Some(62_000),
        "and the drift clock is NOT cleared by going dark"
    );
}

#[test]
fn the_clock_going_backwards_is_treated_as_due_rather_than_as_permanent_freshness() {
    let k = key(1);
    let endpoint = CardEndpoint::serving(&signed_by(&k, a_card("decompose a goal")));
    let mut reg = a_registration();
    let pin_cfg = signed_pin(&k);

    pass(&mut reg, &pin_cfg, &endpoint, 1_000_000, false);
    assert_eq!(
        pass(&mut reg, &pin_cfg, &endpoint, 500_000, false).due,
        Due::ClockWentBackwards,
        "a corrected or tampered clock must not read as an upstream that never needs checking again"
    );
}

#[test]
fn the_cadence_grammar_has_no_knob_that_slows_detection_or_delays_demotion() {
    // THE RATCHET. The asymmetry is one line away from being lost to a well-meaning
    // `detection_backoff:` or `demotion_grace:`, and both would be a window an upstream can open
    // for itself by flapping. The cadence's own field set is enumerated here, and the ONLY held
    // direction it may name is recovery.
    // `reverify.rs` moved to `src/trust/` when the MCP refresh timer became its second consumer.
    // The ratchet moved with it — a path that silently stopped resolving would be this guard
    // quietly covering nothing, which is the failure mode it exists to prevent, turned inward.
    let read = |rel: &str| -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
            .unwrap_or_else(|e| {
                panic!(
                    "the cadence ratchet cannot read `{rel}`: {e}. If the file \
                 moved, MOVE THE RATCHET — do not drop the path."
                )
            })
    };
    let reverify_src = read("src/trust/reverify.rs");
    let config_src = read("src/a2a/config.rs");
    let verify_src = read("src/a2a/verify.rs");
    // THE OTHER PLANE'S CADENCE, held to the identical rule, PLUS THE SHARED JOB BOTH PLANES NOW
    // RUN. MCP has a `refresh_ttl:` and a sweep of its own, and both drive the SAME `due`. A knob
    // that slowed detection or delayed a quarantine would be exactly as dangerous there, and a
    // ratchet that guarded only the plane it was written for would be the plane-local drift this
    // release has already been bitten by. `trust/sweep.rs` is the one place a tick interval or a
    // per-registration cooldown could now be introduced for BOTH planes at once, which makes it the
    // single most important file on this list.
    let mcp_config_src = read("src/mcp/config.rs");
    let mcp_sweep_src = read("src/mcp/connect.rs");
    let shared_sweep_src = read("src/trust/sweep.rs");

    let code = |s: &str| -> String {
        s.lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    for (what, src) in [
        ("trust/reverify.rs", code(&reverify_src)),
        ("a2a/config.rs", code(&config_src)),
        ("a2a/verify.rs", code(&verify_src)),
        ("mcp/config.rs", code(&mcp_config_src)),
        ("mcp/connect.rs", code(&mcp_sweep_src)),
        ("trust/sweep.rs", code(&shared_sweep_src)),
    ] {
        for banned in [
            "detection_backoff",
            "detection_grace",
            "demotion_backoff",
            "demotion_grace",
            "demotion_delay",
            "quarantine_grace",
            "quarantine_delay",
            "drift_grace",
            "suppress_drift",
            "min_drift",
        ] {
            assert!(
                !src.contains(banned),
                "{what} names `{banned}`. Detection is never rate-limited and demotion is never \
                 held; the only direction that may be held is RECOVERY. A window an upstream can \
                 open for itself by flapping is a window it will use."
            );
        }
    }

    // And the policy type itself carries exactly two knobs, so a third cannot arrive unnoticed.
    // Exhaustive destructure, no `..`.
    let crate::a2a::reverify::Policy {
        ttl_ms,
        recovery_backoff_ms,
    } = crate::a2a::reverify::Policy {
        ttl_ms: 1,
        recovery_backoff_ms: 2,
    };
    assert_eq!((ttl_ms, recovery_backoff_ms), (1, 2));
}

// ══ THE DISCOVERY PATHS ══════════════════════════════════════════════════════════════════════════

#[test]
fn the_legacy_well_known_path_is_tried_only_when_the_canonical_one_served_nothing() {
    // Both paths are tolerated because the path moved between revisions. But a card that was
    // FETCHED and then FAILED VERIFICATION is not retried at the older path: retrying would let an
    // upstream serve a signed card at one path and a hostile one at the other, and have the hostile
    // one reached whenever the signed one is the first to be refused.
    struct LegacyOnly {
        canonical_hits: RefCell<u32>,
        body: Vec<u8>,
    }
    impl Transport for LegacyOnly {
        fn get(&self, url: &reqwest::Url, _addr: IpAddr) -> Result<HttpResponse, String> {
            if url.path() == crate::a2a::card::WELL_KNOWN_CARD_PATH {
                *self.canonical_hits.borrow_mut() += 1;
                return Ok(HttpResponse {
                    status: 404,
                    location: None,
                    body: Vec::new(),
                    peer_spki: None,
                });
            }
            Ok(HttpResponse {
                status: 200,
                location: None,
                body: self.body.clone(),
                peer_spki: None,
            })
        }
    }

    let k = key(1);
    let legacy = LegacyOnly {
        canonical_hits: RefCell::new(0),
        body: serde_json::to_vec(&signed_by(&k, a_card("decompose a goal"))).expect("serialize"),
    };
    let mut reg = a_registration();
    let p = reverify_once(
        &mut reg,
        &signed_pin(&k),
        &FixedResolver,
        &legacy,
        &FetchPolicy::default(),
        1_000,
        false,
    );
    assert!(
        p.refusal.is_none(),
        "the legacy path must be tolerated: {p:?}"
    );
    assert_eq!(
        *legacy.canonical_hits.borrow(),
        1,
        "canonical is tried FIRST"
    );

    // Now the canonical path serves a card signed by the WRONG key while the legacy path serves a
    // good one. The refusal must stand: verification failure does not fall through to the old path.
    struct SplitBrain {
        good: Vec<u8>,
        bad: Vec<u8>,
    }
    impl Transport for SplitBrain {
        fn get(&self, url: &reqwest::Url, _addr: IpAddr) -> Result<HttpResponse, String> {
            let body = if url.path() == crate::a2a::card::WELL_KNOWN_CARD_PATH {
                self.bad.clone()
            } else {
                self.good.clone()
            };
            Ok(HttpResponse {
                status: 200,
                location: None,
                body,
                peer_spki: None,
            })
        }
    }
    let split = SplitBrain {
        good: serde_json::to_vec(&signed_by(&k, a_card("decompose a goal"))).expect("serialize"),
        bad: serde_json::to_vec(&signed_by(&key(2), a_card("decompose a goal")))
            .expect("serialize"),
    };
    let mut reg = a_registration();
    let p = reverify_once(
        &mut reg,
        &signed_pin(&k),
        &FixedResolver,
        &split,
        &FetchPolicy::default(),
        1_000,
        false,
    );
    assert_eq!(
        p.refusal,
        Some(VerifyRefusal::Jws(
            crate::a2a::jws::JwsError::NoSignatureVerified
        )),
        "a verification failure at the canonical path must NOT fall through to the legacy one"
    );
}

// ══ THE BREAKER RUNS ON THE SAME PASS ════════════════════════════════════════════════════════════

#[test]
fn the_breaker_is_applied_on_the_pass_rather_than_waiting_for_the_next_timer() {
    let k = key(1);
    let endpoint = CardEndpoint::serving(&signed_by(&k, a_card("decompose a goal")));
    let mut reg = a_registration();
    let pin_cfg = signed_pin(&k);

    pass(&mut reg, &pin_cfg, &endpoint, 1_000, false);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");

    reg.thresholds = crate::a2a::anomaly::Thresholds {
        min_observations: 10,
        terminal_failure_rate: Some(0.4),
        ..Default::default()
    };
    reg.window = crate::a2a::anomaly::Window {
        observations: 50,
        terminal_failures: 40,
        first_observation_ms: 1_000,
        last_observation_ms: 60_000,
        ..Default::default()
    };

    let p = pass(&mut reg, &pin_cfg, &endpoint, 62_000, false);
    let trip = p.trip.expect("the breaker must trip on this pass");
    assert_eq!(trip.signal.label(), "terminal_failure_rate");
    assert_eq!(
        reg.trust_state(),
        TrustState::Suspended,
        "suspension OUTRANKS a card that is entirely in order"
    );
    assert!(!reg.is_delegable());
}

// ══ THE VERB LAYER'S SEAMS, IMPLEMENTED ══════════════════════════════════════════════════════════

#[test]
fn the_probe_hands_the_verb_layer_the_document_as_received_and_the_observation_over_it() {
    // The verbs take fetch and verify as traits. This is the production implementation of both, and
    // what it must get right is that the RAW document travels: the fingerprint covers members
    // busbar does not model, so a probe that handed on a parsed projection would make the pin blind
    // to exactly the silent rug-pull it exists to catch.
    use crate::a2a::verbs::{CardObserver, CardSource};

    let k = key(1);
    let mut card = a_card("decompose a goal");
    card.as_object_mut()
        .expect("object")
        .insert("x-vendor-extension".to_string(), json!({ "region": "eu" }));
    let signed = signed_by(&k, card);
    let endpoint = CardEndpoint::serving(&signed);
    let reg = a_registration();
    let pin_cfg = signed_pin(&k);
    let policy = FetchPolicy::default();
    let probe = RegistrationProbe {
        registration: &reg,
        pin_cfg: &pin_cfg,
        resolver: &FixedResolver,
        transport: &endpoint,
        policy: &policy,
    };

    let fetched = probe.fetch_card("planner").expect("fetch");
    assert_eq!(
        fetched.document, signed,
        "the document travels AS RECEIVED, unmodelled members and all"
    );
    assert_eq!(
        crate::a2a::card::fingerprint(&fetched.document).expect("fingerprint"),
        crate::a2a::card::fingerprint(&signed).expect("fingerprint")
    );

    let observation = probe.observe(&fetched).expect("observe");
    assert!(observation.capabilities.contains_key("plan"));
    assert!(matches!(
        observation.pin,
        Some(CardPin::JwsIssuerKey { .. })
    ));

    // A probe is bound to ONE registration and refuses to answer about another: a probe answering
    // about an agent it was not built for is a cross-registration confusion in the one place where
    // the answer becomes an approval.
    let err = probe.fetch_card("summarizer").expect_err("wrong agent");
    assert!(err.contains("built for agent `planner`"), "got {err}");

    // And a verification failure surfaces through the observer's `Err` arm, which is the same arm a
    // contact failure lands in downstream — neither may ever read as "unchanged".
    let wrong_key = signed_pin(&key(2));
    let wrong = RegistrationProbe {
        registration: &reg,
        pin_cfg: &wrong_key,
        resolver: &FixedResolver,
        transport: &endpoint,
        policy: &policy,
    };
    assert!(wrong.observe(&fetched).is_err());
}
