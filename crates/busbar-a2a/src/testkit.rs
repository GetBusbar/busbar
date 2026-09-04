// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S TEST-KIT — the fixture surface that names A2A plane types, kept ON THE PLANE, so
//! busbar-core's neutral `test_support::TestApp` names none of them.
//!
//! Before the plane split, `TestApp` in busbar-core built the A2A plane runtime itself (naming
//! `crate::a2a::*` back INTO core through the `#[path]` dual-compile). Now the `agents:` builder
//! methods live here as an extension trait over the neutral `busbar_substrate::testkit::TestAppSeam`
//! (which core implements for its `TestApp`), and they lower to the real, externally-linked
//! `busbar-a2a` crate through core's neutral install seams
//! (`install_plane_runtime`, `mount_plane`/`admit_plane`, `set_container_hooks`,
//! `set_plane_defs_any`), reading `public_url` / the card issuer back through the neutral getters.

use crate::a2a::config::{AgentDefCfg, AgentsCfg};
use crate::a2a::plane::A2aPlane;
use busbar_substrate::testkit::{TestAppSeam, TestAppSeamExt};
use std::sync::Arc;

// The self-enveloping admin-verb backing (core's `CorePlaneAdminEnvelope`) — bound plane-side so the
// router that serves a plane verb has THIS crate's core copy's envelope, matching its recording
// middleware's condition `Tag` type. The one core-implementation name lives in this `tests/`-path file the
// neutral-purity lint excludes (the twin of core's `plane/tests/registry_tests.rs`).
#[path = "a2a/tests/envelope_boot.rs"]
mod envelope_boot;

/// The A2A plane's scratch key — the same string as `PLANE_DECL.key`.
const SCRATCH_KEY: &str = "a2a";

/// INSTALL THE A2A CROSS-PLANE TEST SEAMS the composition root (`main`) installs in production — the
/// parse-time section-list provider and the self-enveloping admin-verb backing. Idempotent set-once
/// installs. The durable task set (`crate::taskstore::TASKS`) is owned by the plane and drives the
/// generic `PlaneRecord` store directly, so there is no task codec/reader seam to install here any
/// more (both were deleted with the relocation).
pub fn install_test_seams() {
    busbar_substrate::plane::config::install_plane_sections(
        busbar_substrate::plane::config::default_plane_sections,
    );
    // The self-enveloping admin-verb backing (core's `CorePlaneAdminEnvelope`), bound plane-side from
    // THIS crate's core copy through the `tests/`-path `envelope_boot` helper (the composition-root job
    // `main` does in production) — so the plane's shipped source names no core implementation item.
    envelope_boot::install();
    // Register the A2A plane in the process registry too (config sections / cross-plane refusal), the
    // same thing the finalizer does for plane-building tests.
    busbar_substrate::plane::registry::register_test_plane(&crate::PLANE_DECL);
}

/// The A2A plane's accumulated fixture state, mutated across the fluent chain and consumed once by
/// [`finalize`] at build time.
#[derive(Default)]
pub(crate) struct A2aScratch {
    agent_defs: AgentsCfg,
    registered: bool,
}

fn scratch(app: &mut dyn TestAppSeam) -> &mut A2aScratch {
    let needs_register = !app.plane_scratch::<A2aScratch>(SCRATCH_KEY).registered;
    if needs_register {
        app.plane_scratch::<A2aScratch>(SCRATCH_KEY).registered = true;
        app.register_plane_finalizer(Box::new(finalize));
    }
    app.plane_scratch::<A2aScratch>(SCRATCH_KEY)
}

/// BUILD-TIME FINALIZER: consume the accumulated [`A2aScratch`] and install the real A2A plane through
/// core's neutral seams. Mirrors what busbar-core's `TestApp::build`/`build_a2a_plane_runtime` did.
fn finalize(app: &mut dyn TestAppSeam) {
    // Register this plane in the process registry the way production's composition root does.
    busbar_substrate::plane::registry::register_test_plane(&crate::PLANE_DECL);
    let scratch = app.take_plane_scratch::<A2aScratch>(SCRATCH_KEY);

    // Always carry the type-erased `agents:` handle onto the App (production fidelity; no test-path
    // consumer downcasts it — the plane reads its `AgentsCfg` off its runtime object).
    app.set_plane_defs_any(crate::PLANE_DECL.key, Arc::new(scratch.agent_defs.clone()));

    // The per-agent hook SPECS as neutral strings — core resolves the gates like production does.
    let containers: Vec<(String, Vec<String>)> = scratch
        .agent_defs
        .agents
        .iter()
        .map(|(n, d)| (n.clone(), d.hooks.clone()))
        .collect();
    app.set_container_hooks(
        crate::PLANE_DECL.key,
        containers,
        scratch.agent_defs.all_agent_hooks.clone(),
    );

    // THE A2A RUNTIME, when a receiving side is configured. MIRROR production's `a2a_start` hook:
    // stamp busbar's PUBLIC card-issuer key (off governance, via the neutral getter) onto the plane.
    if let Some(plane) = A2aPlane::from_config(&scratch.agent_defs, app.configured_public_url()) {
        if let Some(issuer) = app.card_issuer(crate::PLANE_DECL.key) {
            plane.set_card_issuer(issuer);
        }
        let admission = plane.admission();
        app.install_plane_runtime(crate::PLANE_DECL.key, plane);
        // Mount the JSON-RPC front door AND the gRPC path (a claimed path is where the RFC 8707
        // audience is found), and wire the admission when the plane claims/admits anything.
        app.mount_plane(
            crate::PLANE_DECL.key,
            crate::a2a::serve::MOUNT_PATH,
            busbar_substrate::plane::WIRE_JSONRPC,
        );
        app.mount_plane(
            crate::PLANE_DECL.key,
            crate::a2a::serve::GRPC_MOUNT_PATH,
            busbar_substrate::plane::WIRE_GRPC,
        );
        if let Some(admission) = admission {
            app.admit_plane(crate::PLANE_DECL.key, admission);
        }
    }
}

/// An UNPINNED receiving `agents:` entry at `url`, for busbar-core integration tests that register a
/// custom agent. Built here because `AgentDefCfg`/`AgentPinCfg` fields are crate-private.
pub fn unpinned_agent(url: &str) -> AgentDefCfg {
    use crate::a2a::config::{AgentPinCfg, PinMechanism};
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

/// An `agents:` config with ONE receiving agent (`planner`), for busbar-core's cross-plane
/// integration tests (they set it on `RootCfg::agent_defs` and boot through `build_app_from_config`).
/// Lives here because the `AgentsCfg`/`AgentDefCfg` fields are crate-private; core names only the
/// returned `AgentsCfg`.
pub fn agents_cfg_with_one_receiving_agent() -> AgentsCfg {
    use crate::a2a::config::{AgentPinCfg, PinMechanism};
    let mut cfg = AgentsCfg::default();
    cfg.agents.insert(
        "planner".to_string(),
        AgentDefCfg {
            url: "https://agent.example/planner".to_string(),
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
        },
    );
    cfg
}

/// The A2A plane's fixture builder methods, as an extension of the neutral `TestApp`. Every method
/// keeps the exact name/shape the in-core builders had, so the plane's own tests read unchanged aside
/// from a `use busbar_a2a::testkit::TestAppA2aExt;`.
pub trait TestAppA2aExt {
    /// Seed an `agents:` DEFINITION into the App's effective named map.
    fn agent_def(self, name: &str, cfg: AgentDefCfg) -> Self;
    /// The reserved section-level `agents.hooks:` attach — the all-A2A hook list.
    fn agents_hooks(self, names: &[&str]) -> Self;
}

impl<A: TestAppSeam> TestAppA2aExt for A {
    fn agent_def(mut self, name: &str, cfg: AgentDefCfg) -> Self {
        scratch(&mut self)
            .agent_defs
            .agents
            .insert(name.into(), cfg);
        self
    }

    fn agents_hooks(mut self, names: &[&str]) -> Self {
        scratch(&mut self).agent_defs.all_agent_hooks =
            names.iter().map(|n| (*n).to_string()).collect();
        self
    }
}
