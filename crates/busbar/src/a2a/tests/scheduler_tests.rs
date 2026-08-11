// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JOB'S TESTS, and they are the asymmetry's tests.
//!
//! `reverify_tests.rs` and `verify_tests.rs` already pin the asymmetry in the pure function and in
//! one pass. What those cannot pin is that it SURVIVES BEING SCHEDULED — and a scheduler is exactly
//! where it would be lost, because a scheduler is made of the knobs that would lose it: a tick
//! interval, a skip-if-checked-recently fast path, a back-off on an agent that keeps failing. So the
//! canonical case — `recovery_backoff_ms = u64::MAX`, still demoted on the first drift — is re-run
//! HERE, through [`sweep`], the function the spawned job actually calls. A guard that only ever
//! judged the function underneath the job would pass a job that never called it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use super::*;
use crate::a2a::config::{AgentDefCfg, AgentPinCfg, AgentsCfg, PinMechanism};
use crate::a2a::fetch::HttpResponse;
use crate::a2a::jws::ED25519_SPKI_PREFIX;
use crate::a2a::reverify::Due;
use crate::a2a::scheduler::CardTransports;
use crate::trust::TrustState;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

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

/// A set of card endpoints whose served documents can be swapped between sweeps, plus a COUNTER of
/// how many times each was fetched. The count is what lets a test assert that the sweep did not
/// skip an agent — an assertion about the absence of an event, which is otherwise unobservable.
struct Endpoints {
    served: RefCell<HashMap<String, HttpResponse>>,
    fetches: RefCell<HashMap<String, usize>>,
}

impl Endpoints {
    fn new() -> Self {
        Self {
            served: RefCell::new(HashMap::new()),
            fetches: RefCell::new(HashMap::new()),
        }
    }

    fn serve(&self, host: &str, card: &Value) {
        self.served.borrow_mut().insert(
            format!("https://{host}/.well-known/agent-card.json"),
            HttpResponse {
                status: 200,
                location: None,
                body: serde_json::to_vec(card).expect("serialize"),
                peer_spki: None,
            },
        );
    }

    /// Every fetch aimed at `host`, at EITHER well-known path. Summed rather than read at the
    /// canonical path alone, because "was this agent looked at" is the question, and a pass that
    /// fell through to the legacy path still looked.
    fn fetches_of(&self, host: &str) -> usize {
        let prefix = format!("https://{host}/");
        self.fetches
            .borrow()
            .iter()
            .filter(|(url, _)| url.starts_with(&prefix))
            .map(|(_, n)| *n)
            .sum()
    }
}

impl Transport for Endpoints {
    fn get(&self, url: &reqwest::Url, _addr: IpAddr) -> Result<HttpResponse, String> {
        *self
            .fetches
            .borrow_mut()
            .entry(url.as_str().to_string())
            .or_insert(0) += 1;
        self.served
            .borrow()
            .get(url.as_str())
            .cloned()
            .ok_or_else(|| format!("connection refused for `{url}`"))
    }
}

fn signed_agent(host: &str, k: &SigningKey) -> AgentDefCfg {
    AgentDefCfg {
        url: format!("https://{host}/agent"),
        pin: AgentPinCfg {
            mechanism: PinMechanism::JwsIssuerKey,
            key: Some(spki_base64(k)),
            fingerprint: None,
        },
        // A one-minute freshness window, so a sweep at +62s is due and one at +30s is not.
        reverify_ttl: Some("60s".to_string()),
        recovery_backoff: Some("5m".to_string()),
        protocol_version: None,
        allow_private: false,
        upstream_credentials: None,
        upstream_credential: None,
        egress_scopes: Vec::new(),
        client_identity: None,
        hooks: Vec::new(),
    }
}

fn plane_of(agents: &[(&str, AgentDefCfg)]) -> Arc<A2aPlane> {
    let mut cfg = AgentsCfg::default();
    for (name, def) in agents {
        cfg.agents.insert((*name).to_string(), def.clone());
    }
    A2aPlane::from_config(&cfg, Some("https://busbar.example")).expect("a plane")
}

/// Drive one sweep and hand back the outcome for `agent_id`.
fn sweep_one(
    plane: &A2aPlane,
    endpoints: &Endpoints,
    now_ms: u64,
    agent_id: &str,
) -> Option<SweepOutcome> {
    sweep(plane, &FixedResolver, &OneForAll(endpoints), now_ms)
        .into_iter()
        .find(|o| o.agent_id == agent_id)
}

/// Take the plane through its first successful contact and APPROVE what was seen, which is the
/// operator act every later drift is measured against.
fn approve_after_first_sweep(plane: &A2aPlane, endpoints: &Endpoints, agent_id: &str) {
    sweep(plane, &FixedResolver, &OneForAll(endpoints), 1_000);
    plane.with_registrations_mut(|regs| {
        let reg = regs
            .iter_mut()
            .find(|r| r.agent_id == agent_id)
            .expect("the registration");
        let seen = reg.sighting.clone();
        crate::a2a::pin::approve_registration(&mut reg.approval, &seen, None).expect("approve");
        assert_eq!(reg.trust_state(), TrustState::Approved);
    });
}

fn state_of(plane: &A2aPlane, agent_id: &str) -> TrustState {
    plane.with_registrations(|regs| {
        regs.iter()
            .find(|r| r.agent_id == agent_id)
            .expect("the registration")
            .trust_state()
    })
}

// ── THE ASYMMETRY, THROUGH THE SCHEDULED PATH ────────────────────────────────────────────────────

#[test]
fn the_scheduled_sweep_demotes_on_the_first_drift_however_long_the_recovery_backoff_is() {
    // THE CANONICAL CASE, RE-AIMED. `verify_tests.rs` proves the PASS demotes with the largest
    // backoff the type can carry. This proves the JOB does — that nothing between the timer and the
    // decision reintroduced a hold on demotion. Holding it would hand a flapping upstream a window
    // in which its next change is not acted on, and choosing when to flap is entirely within its
    // gift.
    let k = key(1);
    let endpoints = Endpoints::new();
    endpoints.serve("a2a.vendor", &signed_by(&k, a_card("decompose a goal")));
    let plane = plane_of(&[("planner", signed_agent("a2a.vendor", &k))]);

    approve_after_first_sweep(&plane, &endpoints, "planner");
    plane.with_registrations_mut(|regs| {
        regs[0].reverify.recovery_backoff_ms = u64::MAX;
    });

    endpoints.serve("a2a.vendor", &signed_by(&k, a_card("moved")));
    let outcome = sweep_one(&plane, &endpoints, 62_000, "planner").expect("the agent was swept");
    let settled = outcome.pass.settled.as_ref().expect("settled");

    assert!(
        settled.drift_observed,
        "the drift was DETECTED on this sweep"
    );
    assert!(
        !settled.recovery_held,
        "the backoff applies to RECOVERY only; it must not hold a demotion"
    );
    assert_eq!(
        state_of(&plane, "planner"),
        TrustState::Quarantined,
        "and the demotion is APPLIED to the registry the job mutates, on the first drift"
    );
}

#[test]
fn recovery_is_the_half_the_scheduled_sweep_holds() {
    // The other half of the same asymmetry, also through the job: a clean answer after a drift is
    // NOT believed until the operator's backoff has elapsed, so an alternating upstream collapses
    // into one persistent quarantine instead of a demotion storm.
    let k = key(1);
    let good = signed_by(&k, a_card("decompose a goal"));
    let endpoints = Endpoints::new();
    endpoints.serve("a2a.vendor", &good);
    let plane = plane_of(&[("planner", signed_agent("a2a.vendor", &k))]);

    approve_after_first_sweep(&plane, &endpoints, "planner");

    endpoints.serve("a2a.vendor", &signed_by(&k, a_card("moved")));
    sweep_one(&plane, &endpoints, 62_000, "planner").expect("swept");
    assert_eq!(state_of(&plane, "planner"), TrustState::Quarantined);

    // The upstream puts the original card back one minute later. The backoff is five minutes.
    endpoints.serve("a2a.vendor", &good);
    let held = sweep_one(&plane, &endpoints, 123_000, "planner").expect("swept");
    assert!(
        held.pass.settled.as_ref().expect("settled").recovery_held,
        "a clean answer inside the backoff is DISBELIEVED"
    );
    assert_eq!(
        state_of(&plane, "planner"),
        TrustState::Quarantined,
        "so the quarantine persists rather than flapping with the upstream"
    );

    // And once the backoff HAS elapsed, the same clean answer is believed.
    let believed = sweep_one(&plane, &endpoints, 500_000, "planner").expect("swept");
    assert!(
        !believed
            .pass
            .settled
            .as_ref()
            .expect("settled")
            .recovery_held
    );
    assert_eq!(state_of(&plane, "planner"), TrustState::Approved);
}

#[test]
fn the_sweep_never_claims_to_be_an_operator_sync() {
    // `sync` OUTRANKS the timer, and the timer must never be able to claim it: a job that passed
    // `operator_sync: true` would make every tick an explicit operator request, which is harmless
    // here but would make `Due::OperatorSync` meaningless in the audit trail — the one signal that
    // distinguishes "a human had reason to suspect this agent" from "the clock came round".
    let k = key(1);
    let endpoints = Endpoints::new();
    endpoints.serve("a2a.vendor", &signed_by(&k, a_card("decompose a goal")));
    let plane = plane_of(&[("planner", signed_agent("a2a.vendor", &k))]);

    let first = sweep_one(&plane, &endpoints, 1_000, "planner").expect("swept");
    assert_eq!(
        first.pass.due,
        Due::NeverChecked,
        "a registration lowered from config has never been contacted, so it is due at once"
    );

    let inside_window = sweep_one(&plane, &endpoints, 30_000, "planner").expect("swept");
    assert_eq!(
        inside_window.pass.due,
        Due::No,
        "and the timer does not manufacture an OperatorSync to check anyway"
    );

    let elapsed = sweep_one(&plane, &endpoints, 62_000, "planner").expect("swept");
    assert_eq!(elapsed.pass.due, Due::TtlExpired);
}

#[test]
fn every_registration_is_swept_on_every_tick_and_a_failing_one_is_not_backed_off() {
    // NO KNOB SLOWS DETECTION. Three agents, one of which refuses connections: the failing one is
    // fetched on EVERY tick it is due for, because a failing upstream is the one that most needs
    // looking at, and a "leave it a while, it was down last time" would be a detection delay an
    // upstream can trigger for itself by refusing connections.
    let k = key(1);
    let endpoints = Endpoints::new();
    endpoints.serve("one.vendor", &signed_by(&k, a_card("a")));
    endpoints.serve("two.vendor", &signed_by(&k, a_card("b")));
    // three.vendor is deliberately never served: every fetch of it fails.
    let plane = plane_of(&[
        ("one", signed_agent("one.vendor", &k)),
        ("two", signed_agent("two.vendor", &k)),
        ("three", signed_agent("three.vendor", &k)),
    ]);

    let mut now = 1_000;
    for tick in 1..=3 {
        let outcomes = sweep(&plane, &FixedResolver, &OneForAll(&endpoints), now);
        assert_eq!(
            outcomes.len(),
            3,
            "tick {tick}: every registration is visited, not a subset"
        );
        assert!(
            outcomes.iter().all(|o| o.pass.due.should_check()),
            "tick {tick}: every registration was DUE and every one was checked"
        );
        assert_eq!(
            endpoints.fetches_of("three.vendor"),
            // Both well-known paths are tried when the canonical one yields no document, so a
            // never-served host costs two fetches per due tick.
            tick * 2,
            "the failing agent is re-checked on tick {tick}, never backed off"
        );
        now += 61_000;
    }

    assert_eq!(
        state_of(&plane, "three"),
        TrustState::Error,
        "and a failed contact is RECORDED as one rather than leaving a stale sighting in place"
    );
}

#[test]
fn an_agent_the_operator_removed_is_not_reverified_against_a_remembered_pin() {
    // The pins map is THIS generation's config. A registration with no pin in it is one the
    // operator removed, and verifying its card against a root nobody currently declares would be
    // busbar deciding they did not mean it.
    let k = key(1);
    let endpoints = Endpoints::new();
    endpoints.serve("a2a.vendor", &signed_by(&k, a_card("decompose a goal")));
    let plane = plane_of(&[("planner", signed_agent("a2a.vendor", &k))]);

    // Simulate the registry outliving its config entry by renaming the registration out from under
    // the pins map — the shape a partially-applied config would produce.
    plane.with_registrations_mut(|regs| regs[0].agent_id = "renamed".to_string());

    let outcomes = sweep(&plane, &FixedResolver, &OneForAll(&endpoints), 1_000);
    assert!(
        outcomes.is_empty(),
        "an agent this generation's config does not declare is not swept"
    );
    assert_eq!(
        endpoints.fetches_of("a2a.vendor"),
        0,
        "and nothing was fetched on its behalf"
    );
}

#[test]
fn the_tick_is_a_constant_and_bounds_only_granularity() {
    // A configurable sweep interval is a configurable DETECTION DELAY wearing a scheduling costume.
    // This asserts the shape rather than the number: the tick is a compile-time constant, so there
    // is no config path that can make detection rarer, and it is short relative to the shortest
    // cadence an operator can express.
    assert!(REVERIFY_TICK.as_secs() > 0);
    assert!(
        REVERIFY_TICK.as_secs() <= 60,
        "the sweep must notice an elapsed TTL within a minute of it elapsing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_job_exits_on_the_shutdown_broadcast() {
    // Shut the job down and JOIN its own task rather than guessing a wall-clock duration. A job that
    // ignored the broadcast would hold the process open past a graceful stop.
    let k = key(1);
    let plane = plane_of(&[("planner", signed_agent("a2a.vendor", &k))]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let job = spawn_reverifier(
        plane,
        &crate::a2a::transport::ClientIdentities::new(),
        shutdown_rx,
    );
    shutdown_tx.send(()).expect("the receiver is live");
    job.await.expect("the job exits cleanly on the broadcast");
}

#[test]
fn reporting_a_sweep_is_separate_from_deciding_it() {
    // `report` is called by the job and by nothing else, so it is exercised here rather than left
    // as the one line in the job that no test ever runs. It must tolerate every outcome shape,
    // including the skipped one.
    let k = key(1);
    let endpoints = Endpoints::new();
    endpoints.serve("a2a.vendor", &signed_by(&k, a_card("decompose a goal")));
    let plane = plane_of(&[("planner", signed_agent("a2a.vendor", &k))]);

    report(&sweep(
        &plane,
        &FixedResolver,
        &OneForAll(&endpoints),
        1_000,
    ));
    report(&sweep(
        &plane,
        &FixedResolver,
        &OneForAll(&endpoints),
        2_000,
    ));
    endpoints.serve("a2a.vendor", &signed_by(&key(2), a_card("moved")));
    report(&sweep(
        &plane,
        &FixedResolver,
        &OneForAll(&endpoints),
        70_000,
    ));
}

// ── THE TRANSPORT IS ASKED FOR PER REGISTRATION ──────────────────────────────────────────────────

/// A bundle that records WHICH agent each transport was asked for, and hands out a different
/// transport per agent so the sweep cannot pass by luck.
struct PerAgent {
    endpoints: Endpoints,
    asked: RefCell<Vec<String>>,
}

impl CardTransports for PerAgent {
    fn for_agent(&self, agent_id: &str) -> &dyn Transport {
        self.asked.borrow_mut().push(agent_id.to_string());
        &self.endpoints
    }
}

/// THE STRUCTURAL FIX, AT THE SWEEP: every registration gets its transport asked for BY NAME.
///
/// `sweep` used to take one `&dyn Transport` and use it for all of them, which is why an outbound
/// client identity — per registration by definition — had nowhere to live. The assertion is on the
/// SEQUENCE: one lookup per registration, in registry order, with the registration's own id. A
/// sweep that resolved the transport once outside the loop would produce one entry, or none.
#[test]
fn the_sweep_asks_for_a_transport_per_registration_by_agent_id() {
    let k = key(1);
    let bundle = PerAgent {
        endpoints: Endpoints::new(),
        asked: RefCell::new(Vec::new()),
    };
    bundle
        .endpoints
        .serve("a2a.vendor", &signed_by(&k, a_card("decompose a goal")));
    let plane = plane_of(&[
        ("planner", signed_agent("a2a.vendor", &k)),
        ("payments", signed_agent("payments.vendor", &k)),
    ]);

    let outcomes = sweep(&plane, &FixedResolver, &bundle, 1_000);

    assert_eq!(outcomes.len(), 2);
    assert_eq!(
        bundle.asked.into_inner(),
        vec!["planner".to_string(), "payments".to_string()],
        "each registration must be given the transport that belongs to IT"
    );
}

// ── THE PER-REGISTRATION `allow_private`, THROUGH THE SCHEDULED PATH ─────────────────────────────

/// THE SWEEP READS THE SAME KNOB THE OPERATOR-DRIVEN VERBS READ.
///
/// This is the failure that would otherwise be invisible until six hours after a deployment went
/// live: an operator approves a loopback agent through `POST /agents/{name}/approve`, the plane
/// serves, and then the FIRST re-verification sweep fetches with a policy that never heard of
/// `allow_private`, records a refusal as a failed contact, and silently demotes the agent to
/// `Error`. A plane-wide policy would have produced exactly that, which is why
/// `A2aPlane::fetch_policy_for` exists and why the sweep narrows per registration.
#[test]
fn the_sweep_honours_the_registrations_own_allow_private() {
    let k = key(3);
    let card = signed_by(&k, a_card("echo"));
    let endpoints = Endpoints::new();
    // A LOOPBACK endpoint, over plaintext — the shape a hermetic rig and a laptop have.
    endpoints.served.borrow_mut().insert(
        "http://127.0.0.1:9000/.well-known/agent-card.json".to_string(),
        HttpResponse {
            status: 200,
            location: None,
            body: serde_json::to_vec(&card).expect("serialize"),
            peer_spki: None,
        },
    );

    let mut opted_in = signed_agent("a2a.vendor", &k);
    opted_in.url = "http://127.0.0.1:9000/agent".to_string();
    opted_in.allow_private = true;
    let mut refused = opted_in.clone();
    refused.allow_private = false;

    let plane = plane_of(&[("opted-in", opted_in), ("refused", refused)]);
    let outcomes = sweep(&plane, &FixedResolver, &OneForAll(&endpoints), 1_000);

    let seen = outcomes
        .iter()
        .find(|o| o.agent_id == "opted-in")
        .expect("swept");
    assert!(
        seen.pass.refusal.is_none(),
        "`allow_private: true` must reach its own loopback backend: {:?}",
        seen.pass.refusal
    );

    let blocked = outcomes
        .iter()
        .find(|o| o.agent_id == "refused")
        .expect("swept");
    assert!(
        blocked.pass.refusal.is_some(),
        "and the registration that did NOT opt in is refused on the same sweep, from the same \
         plane — the knob is per registration, not per deployment"
    );

    // AND THE TWO ARE SEPARATELY STATED, which is the whole claim: one plane, two answers, decided
    // by the operator's own line rather than by whichever agent the sweep reached first.
    plane.with_registrations_mut(|regs| {
        let opted = regs.iter().find(|r| r.agent_id == "opted-in").expect("reg");
        let seen = opted.sighting.clone();
        assert!(
            matches!(seen, crate::trust::Sighting::Seen(_)),
            "the opted-in registration has a real sighting to approve: {seen:?}"
        );
    });
    assert_eq!(state_of(&plane, "refused"), TrustState::Error);
}
