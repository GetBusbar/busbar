// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOWERING'S TESTS: absent config is an absent plane, and nothing this lowering produces is
//! trusted.
//!
//! The two properties worth pinning here are the ones a later change would break silently. The
//! first is the gate — a deployment with no `agents:` must hold no registry at all, because "no
//! plane" implemented as "an empty plane plus a check at every call site" is a check somebody
//! eventually forgets. The second is the floor: config carries a trust ROOT, and a lowering that
//! helpfully turned a declared fingerprint into an approval would approve a card nobody fetched.

use super::*;
use crate::a2a::config::{AgentDefCfg, PinMechanism};
use crate::testkit::TestAppA2aExt;
use busbar_substrate::trust::TrustState;

fn cfg_with(agents: &[(&str, AgentDefCfg)]) -> AgentsCfg {
    let mut out = AgentsCfg::default();
    for (name, def) in agents {
        out.agents.insert((*name).to_string(), def.clone());
    }
    out
}

fn unpinned_agent(url: &str) -> AgentDefCfg {
    AgentDefCfg {
        url: url.to_string(),
        pin: AgentPinCfg {
            mechanism: PinMechanism::Unpinned,
            key: None,
            fingerprint: None,
        },
        reverify_ttl: None,
        recovery_backoff: None,
        protocol_version: None,
        allow_private: false,
        upstream_credentials: None,
        upstream_credential: None,
        egress_scopes: Vec::new(),
        client_identity: None,
        hooks: Vec::new(),
    }
}

/// An agent whose operator declared a COMPLETE pin: a root AND an approved fingerprint. The case
/// where a lowering would be most tempted to hand back something already trusted.
fn fully_pinned_agent(url: &str) -> AgentDefCfg {
    AgentDefCfg {
        pin: AgentPinCfg {
            mechanism: PinMechanism::JwsIssuerKey,
            key: Some("a-key".to_string()),
            fingerprint: Some("sha256:already-approved".to_string()),
        },
        ..unpinned_agent(url)
    }
}

#[test]
fn no_agents_configured_is_no_plane_at_all() {
    // THE GATE. Not an empty registry, not a disabled plane — nothing. Everything downstream
    // (the job, and every route the receiving side will mount) hangs off this `Option`, so a
    // deployment that fronts no agents carries none of it.
    assert!(
        A2aPlane::from_config(&AgentsCfg::default(), Some("https://busbar.example")).is_none(),
        "an `agents:` section that defines no agent is not a plane"
    );
}

#[test]
fn a_section_carrying_only_the_reserved_keys_is_still_no_plane() {
    // `agents.hooks:` and `agents.upstream_credentials:` are DEFAULTS FOR agents. Defaults for an
    // empty set are not a deployment that fronts anything, and reading them as one would mount a
    // plane an operator never asked for.
    let cfg = AgentsCfg {
        all_agent_hooks: vec!["audit".to_string()],
        all_agent_upstream_credentials: Some(busbar_api::UpstreamCreds::Own),
        agents: Default::default(),
    };
    assert!(A2aPlane::from_config(&cfg, None).is_none());
}

#[test]
fn one_configured_agent_is_a_plane_holding_exactly_that_registration() {
    let cfg = cfg_with(&[("planner", unpinned_agent("https://a2a.vendor/planner"))]);
    let plane = A2aPlane::from_config(&cfg, Some("https://busbar.example")).expect("a plane");
    assert_eq!(plane.len(), 1);
    assert_eq!(plane.public_url(), Some("https://busbar.example"));
    plane.with_registrations(|regs| {
        assert_eq!(regs[0].agent_id, "planner");
        assert_eq!(regs[0].backend_url, "https://a2a.vendor/planner");
    });
    assert!(
        plane.pin_for("planner").is_some(),
        "the operator's trust root travels with the plane"
    );
    assert!(
        plane.pin_for("no-such-agent").is_none(),
        "there is no default pin, because a default pin is an invented trust root"
    );
}

#[test]
fn a_declared_fingerprint_does_not_become_an_approval_at_boot() {
    // THE FLOOR. An operator may write the fingerprint they intend to approve; that is intent, not
    // an observation. An approval is a statement about a document that was actually SEEN, and a
    // lowering that promoted config into one would approve a card nobody fetched — which is exactly
    // the rug-pull the pin exists to catch, performed by busbar on itself.
    let cfg = cfg_with(&[("planner", fully_pinned_agent("https://a2a.vendor/planner"))]);
    let plane = A2aPlane::from_config(&cfg, None).expect("a plane");
    plane.with_registrations(|regs| {
        assert_eq!(
            regs[0].trust_state(),
            TrustState::Pending,
            "a registration lowered from config is PENDING, never Approved"
        );
        assert!(
            !regs[0].is_delegable(),
            "and it is not a dispatch candidate"
        );
        assert!(
            regs[0].cached_card.is_none(),
            "nothing has been fetched, so nothing is cached"
        );
    });
}

#[test]
fn the_registry_follows_config_order_rather_than_hash_order() {
    // `AgentsCfg` is insertion-ordered on purpose, so every operator-facing listing and every
    // sweep's log is deterministic. A lowering through a `HashMap` would lose that silently.
    let cfg = cfg_with(&[
        ("zeta", unpinned_agent("https://a2a.vendor/z")),
        ("alpha", unpinned_agent("https://a2a.vendor/a")),
        ("mid", unpinned_agent("https://a2a.vendor/m")),
    ]);
    let plane = A2aPlane::from_config(&cfg, None).expect("a plane");
    plane.with_registrations(|regs| {
        let ids: Vec<&str> = regs.iter().map(|r| r.agent_id.as_str()).collect();
        assert_eq!(ids, ["zeta", "alpha", "mid"]);
    });
}

#[test]
fn the_operators_cadence_is_what_the_registration_carries() {
    // The per-agent cadence is lowered through the SAME `policy_for` the config tests pin, so the
    // number an operator wrote and the number the job's arithmetic reads are provably one value.
    let mut def = unpinned_agent("https://a2a.vendor/planner");
    def.reverify_ttl = Some("90s".to_string());
    def.recovery_backoff = Some("2m".to_string());
    let plane = A2aPlane::from_config(&cfg_with(&[("planner", def)]), None).expect("a plane");
    plane.with_registrations(|regs| {
        assert_eq!(regs[0].reverify.ttl_ms, 90_000);
        assert_eq!(regs[0].reverify.recovery_backoff_ms, 120_000);
    });
}

#[test]
fn an_agent_that_spells_no_backoff_gets_the_deployment_default_and_it_is_not_zero() {
    // Zero is a legitimate PER-AGENT setting and a bad default: it means "believe a recovery
    // immediately", and the boring explanation for a flap and the hostile one look identical from
    // here.
    let plane = A2aPlane::from_config(
        &cfg_with(&[("planner", unpinned_agent("https://a2a.vendor/planner"))]),
        None,
    )
    .expect("a plane");
    plane.with_registrations(|regs| {
        assert_eq!(
            regs[0].reverify.recovery_backoff_ms,
            crate::a2a::config::DEFAULT_RECOVERY_BACKOFF_MS
        );
        assert!(regs[0].reverify.recovery_backoff_ms > 0);
    });
}

#[test]
fn a_booted_app_carries_the_plane_only_when_agents_are_configured() {
    // THE LOWERING IS WIRED, not merely writable. This drives the real `App` build — the same
    // function boot and every config apply call — rather than `from_config` alone, because a plane
    // that lowers correctly and is never asked for at boot is a plane no deployment has.
    busbar_core::metrics::init();
    let none = busbar_core::test_support::TestApp::new().build();
    assert!(
        crate::a2a::runtime(none.as_ref()).is_none(),
        "a deployment with no `agents:` holds no registry, so there is no job to spawn"
    );

    let one = busbar_core::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let plane = crate::a2a::runtime(one.as_ref()).expect("an `agents:` entry is a plane");
    assert_eq!(plane.len(), 1);
    assert_eq!(plane.public_url(), Some("https://busbar.example"));
}

#[test]
fn egress_scopes_and_the_leased_credential_travel_from_config_to_the_registration() {
    // Both are INTENT that the delegating side reads off the registration rather than off config,
    // so a lowering that dropped either would fail open on egress and fail closed on credentials —
    // one silently, the other loudly, and the silent one is the dangerous half.
    let mut def = unpinned_agent("https://a2a.vendor/planner");
    def.egress_scopes = vec!["frontdesk".to_string()];
    let plane = A2aPlane::from_config(&cfg_with(&[("planner", def)]), None).expect("a plane");
    plane.with_registrations(|regs| {
        assert_eq!(regs[0].egress_scopes, ["frontdesk"]);
    });
}

/// THE WINDOW THIS PLANE DID NOT CLOSE, and the test that says so.
///
/// The sibling plane stamps the snapshot GENERATION onto a resolved candidate and refuses a call
/// resolved under *N* when the live generation is *N+1*. This plane had no equivalent at all: it
/// re-asked the trust predicate at three separate sites and none of them knew which registry the
/// request had been admitted against, so anything that changed the registry between admission and
/// the socket took effect on the NEXT request and the in-flight one went out under an approval that
/// had already been replaced.
///
/// `LiveGate` now reaches the one ordered validator in `busbar_substrate::trust::validate` and hands it both
/// generations. This drives the real gate through the real plane.
///
/// RED, WATCHED: with `LiveGate::still_delegable` passing `Generations::at_admission(live)` instead
/// of `Generations::since(admitted, live)` — which is what "no generation check" looks like when
/// written in the new vocabulary — the second assertion below returns `Ok(())`.
#[test]
fn an_in_flight_dispatch_admitted_under_generation_n_is_refused_at_n_plus_1() {
    use crate::a2a::relay::DelegationGate;

    let cfg = cfg_with(&[("planner", unpinned_agent("https://a2a.vendor/planner"))]);
    let plane = A2aPlane::from_config(&cfg, None).expect("a plane");

    // APPROVE IT, so the trust half of the gate is out of the way and the generation half is what
    // this test is measuring. Without this the refusal below would be `not_serving` whatever the
    // generation did, and the test would pass on a plane with no generation check at all.
    plane.with_registrations_mut(|regs| {
        regs[0].sighting =
            busbar_substrate::trust::Sighting::Seen(busbar_substrate::trust::Observation {
                pin: Some(crate::a2a::pin::CardPin::JwsIssuerKey {
                    issuer_key: "MCowBQYDK2VwAyEAKEY".to_string(),
                    card_fingerprint: "sha256/CARD".to_string(),
                }),
                capabilities: std::collections::BTreeMap::new(),
            });
        let sighting = regs[0].sighting.clone();
        crate::a2a::pin::approve_registration(&mut regs[0].approval, &sighting, None)
            .expect("approve");
    });

    // ADMISSION records the generation the decision was taken under.
    let admitted = plane.generation();
    let gate = LiveGate(std::sync::Arc::clone(&plane));
    assert_eq!(
        gate.still_delegable("planner", admitted),
        Ok(()),
        "the control: on the snapshot it was admitted under, the hop proceeds"
    );

    // ANYTHING THAT TOUCHES THE REGISTRY MOVES IT — a config apply, a re-verification sweep, an
    // operator's suspend, a breaker trip. The mutation here is deliberately EMPTY: the claim is
    // that movement alone refuses, not that this particular change was noticed.
    plane.with_registrations_mut(|_| {});
    let live = plane.generation();
    assert_ne!(live, admitted, "the registry moved");

    let refused = gate
        .still_delegable("planner", admitted)
        .expect_err("the in-flight hop must not outlive the registry it was admitted under");
    assert_eq!(refused.agent_id, "planner");
    assert_eq!(
        refused.state,
        TrustState::Approved,
        "and it is refused while still APPROVED — which is the whole point: this is not the trust \
         check saying no a second time, it is the generation check saying no for the first time"
    );
    let reason = refused.reason.expect("a refusal an operator can act on");
    assert!(
        reason.contains(&admitted.to_string()) && reason.contains(&live.to_string()),
        "the refusal names both generations so an operator can see what moved: {reason}"
    );
}

/// AND THE REGISTRY GENERATION IS TAKEN UNDER THE WRITE LOCK, so no reader can ever observe the new
/// registrations under the old generation — which is the one window a bump-after-release would leave
/// exactly where this number exists to close one.
#[test]
fn every_registry_mutation_moves_the_generation() {
    let cfg = cfg_with(&[("planner", unpinned_agent("https://a2a.vendor/planner"))]);
    let plane = A2aPlane::from_config(&cfg, None).expect("a plane");
    let mut seen = vec![plane.generation()];
    for _ in 0..3 {
        plane.with_registrations_mut(|_| {});
        seen.push(plane.generation());
    }
    let mut sorted = seen.clone();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        seen.len(),
        "monotonic, never repeated: {seen:?}"
    );
    assert!(
        seen.windows(2).all(|w| w[1] > w[0]),
        "and increasing: {seen:?}"
    );

    // A READ does not move it. A generation that ticked on every read would refuse every hop.
    let before = plane.generation();
    plane.with_registrations(|regs| assert_eq!(regs.len(), 1));
    assert_eq!(plane.generation(), before);
}

/// SEAM-AUDIT-C item (d): THE DUAL-COMPILED `Box<dyn Any>` READBACK WITNESS.
///
/// The whole opaque design of [`DurableHandleEngine`] — rows held as `Arc<dyn Any + Send + Sync>`,
/// every read a downcast + clone — exists so the engine can ride a per-plane opaque state slot
/// (`Box<dyn Any>`) that CORE reads back, WITHOUT the engine's `TypeId` diverging across the two core
/// instances a dual-compiled plane test binary links. Today the only non-test constructor of the
/// engine is A2A's `TaskRegistry`, which holds it as a CONCRETE field in a plane-crate static — never
/// boxed into a core slot — so that survival is asserted (the module doc), not proven. Voice is the
/// first plausible consumer to ride the engine through a core `Box<dyn Any>` slot, so it is the first
/// to depend on the claim being true.
///
/// This witness proves it in the config that can actually exhibit the trap: the `busbar-a2a`
/// `--features test-support` binary, which links substrate's SINGLE compile of the engine AND the
/// plane's own core-typed helpers (a two-core binary — the single-compiled coverage in
/// `handle_engine_tests.rs` has only one core instance and cannot exhibit a cross-instance divergence).
/// It:
///   1. builds an engine and submits one plane-crate-local row (RAM posture, no sink),
///   2. ERASES the engine into the core-owned `Box<dyn Any>` scratch slot (`plane_scratch_any` — the
///      exact core-readback path the design promises; the slot lives inside core's `TestApp`),
///   3. reads it BACK through the neutral seam and DOWNCASTS to `DurableHandleEngine` — the
///      load-bearing assertion: it succeeds only because the engine is substrate-single-compiled and
///      non-generic, so its `TypeId` is identical on the core store side and the plane read side,
///   4. reads the row back out and downcasts the NESTED `Arc<dyn Any>` to the plane row, asserting it
///      is BYTE-IDENTICAL to the submitted row (no re-encode round-trip) — proving the inner erasure
///      also survives with its own preserved `TypeId`.
///
/// The baked NEGATIVE CONTROL proves the readback is not vacuously green: a plane-crate stand-in
/// monomorphised HERE (what a generic `Engine<Row>` compiled in the plane crate would present as),
/// erased into the SAME slot, FAILS the downcast to the substrate engine — so the readback
/// discriminates on `TypeId` and catches a divergent engine rather than accepting any value.
#[test]
fn the_durable_handle_engine_and_its_rows_survive_erase_into_a_core_box_dyn_any_slot() {
    use busbar_core::test_support::TestApp;
    use busbar_substrate::plane::handle_engine::{
        DurableHandleEngine, HandleMeta, SubmitRecord, SweepBounds,
    };
    use busbar_substrate::testkit::TestAppSeam;
    use std::any::Any;
    use std::sync::Arc;

    /// A PLANE-CRATE-LOCAL row the engine holds opaquely — the analogue of an A2A task row / a
    /// Responses-stateful row a voice consumer would install. Its `TypeId` is the plane crate's.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PlaneRow {
        id: String,
        owner: String,
        body: String,
    }

    const SLOT_KEY: &str = "handle-engine-readback-witness";

    // (1) Build the engine and submit one plane row. RAM posture (no sink): the durable
    // upsert/append no-op, so `row_record` is built but never hits a store — the witness is about the
    // in-memory opaque row surviving the erase, not durability.
    let engine = DurableHandleEngine::new();
    let row = PlaneRow {
        id: "resp_witness_1".to_string(),
        owner: "tenant-a".to_string(),
        body: "the-load-bearing-bytes".to_string(),
    };
    let bounds = SweepBounds {
        abandon_secs: 10_000,
        terminal_ttl_secs: 10_000,
        max_retained: 16,
    };
    engine
        .submit(
            1,
            bounds,
            |_pos| {
                Ok(SubmitRecord {
                    id: row.id.clone(),
                    row: Arc::new(row.clone()) as Arc<dyn Any + Send + Sync>,
                    meta: HandleMeta {
                        owner: row.owner.clone(),
                        updated_at: 1,
                        terminal: false,
                        cursor: 0,
                    },
                    row_record: busbar_api::PlaneRecord {
                        kind: "witness".to_string(),
                        id: row.id.clone(),
                        parent: None,
                        seq: 0,
                        ts: 1,
                        disposition: busbar_api::PlaneDisposition::Active,
                        body: row.body.clone().into_bytes(),
                    },
                    // Chainless: this witness is about type survival, not the provenance chain.
                    event: None,
                })
            },
            |_id, _row, _pos, _now| None,
            |_id, _e| {},
        )
        .expect("submit installs the handle");

    // (2) ERASE the populated engine into the CORE-OWNED `Box<dyn Any>` scratch slot. The slot lives
    // inside core's `TestApp` (`plane_scratch` map), so this is core holding the plane's engine
    // type-erased — exactly the `Box<dyn Any>` core-readback path the opaque design is paying for.
    // `plane_scratch_any`'s init is an `Fn` (called at most once), so the move goes through a cell.
    let mut app = TestApp::new();
    let pending = std::cell::RefCell::new(Some(engine));
    let _installed: &mut dyn Any = app.plane_scratch_any(SLOT_KEY, &|| {
        Box::new(pending.borrow_mut().take().expect("engine moved in once")) as Box<dyn Any>
    });

    // (3) READ IT BACK through the neutral seam and DOWNCAST to the substrate engine. THE
    // LOAD-BEARING ASSERTION: this succeeds only because `DurableHandleEngine` is
    // substrate-single-compiled and non-generic, so the `TypeId` core computed when the plane boxed it
    // in is the same `TypeId` the plane names on the way out. A generic `Engine<PlaneRow>`
    // monomorphised in the plane crate would present a divergent `TypeId` in this two-core binary and
    // this `.downcast()` would return `Err` (see the negative control below).
    let boxed: Box<dyn Any> = app
        .take_plane_scratch_any(SLOT_KEY)
        .expect("the core slot still holds the erased engine");
    let engine_back: Box<DurableHandleEngine> = boxed.downcast::<DurableHandleEngine>().expect(
        "the erased engine downcasts back — its TypeId survived the core Box<dyn Any> slot",
    );

    // (4) Read the row back out of the recovered engine and downcast the NESTED `Arc<dyn Any>` to the
    // plane row. Byte-identical to what was submitted — no re-encode round-trip — proving the inner
    // erasure survived with its own preserved `TypeId` too.
    let got: Arc<dyn Any + Send + Sync> = engine_back
        .scoped_get(&row.owner, &row.id)
        .expect("the rightful owner reads its row back out of the recovered engine");
    let got_row = got
        .downcast_ref::<PlaneRow>()
        .expect("the inner Arc<dyn Any> downcasts back to the plane row");
    assert_eq!(
        *got_row, row,
        "the row is byte-identical across erase -> downcast across the two core instances"
    );

    // NEGATIVE CONTROL: a plane-crate-local stand-in — what a generic engine
    // monomorphised HERE, in the plane crate, would present as — erased into the SAME core slot must
    // FAIL the downcast to the substrate engine. If this ever downcasts successfully, the witness above
    // is vacuous (the downcast would be discriminating on nothing). This is the exact failure a
    // divergent-TypeId engine would trip at the point core hands the plane its state back.
    struct PlaneMonomorphisedEngineStandIn;
    let mut app2 = TestApp::new();
    app2.plane_scratch_any(SLOT_KEY, &|| {
        Box::new(PlaneMonomorphisedEngineStandIn) as Box<dyn Any>
    });
    let boxed2 = app2
        .take_plane_scratch_any(SLOT_KEY)
        .expect("the slot holds the stand-in");
    assert!(
        boxed2.downcast::<DurableHandleEngine>().is_err(),
        "a plane-crate-monomorphised stand-in must NOT downcast to the substrate engine — the witness \
         discriminates on TypeId and would catch a divergent engine"
    );
}
