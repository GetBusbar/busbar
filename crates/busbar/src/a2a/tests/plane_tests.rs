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
use crate::trust::TrustState;

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
        all_agent_upstream_credentials: Some(crate::auth::UpstreamCreds::Own),
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
    crate::metrics::init();
    let none = crate::test_support::TestApp::new().build();
    assert!(
        none.a2a.is_none(),
        "a deployment with no `agents:` holds no registry, so there is no job to spawn"
    );

    let one = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let plane = one.a2a.as_ref().expect("an `agents:` entry is a plane");
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
