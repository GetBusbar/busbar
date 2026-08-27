// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S TEST-KIT — the fixture surface that names A2A plane types, kept ON THE PLANE, so
//! busbar-core's neutral `test_support::TestApp` names none of them.
//!
//! Before the plane split, `TestApp` in busbar-core built the A2A plane runtime itself (naming
//! `crate::a2a::*` back INTO core through the `#[path]` dual-compile). Now the `agents:` builder
//! methods live here as an extension trait on the neutral `busbar_core::test_support::TestApp`, and
//! they lower to the real, externally-linked `busbar-a2a` crate through core's neutral install seams
//! (`install_plane_runtime`, `mount_plane`/`admit_plane`, `set_a2a_container_hooks`,
//! `set_agent_defs_any`), reading `public_url` / the card issuer back through the neutral getters.

use crate::a2a::config::{AgentDefCfg, AgentsCfg};
use crate::a2a::plane::A2aPlane;
use busbar_core::test_support::TestApp;
use std::sync::Arc;

/// The A2A plane's scratch key — the same string as `PLANE_DECL.key`.
const SCRATCH_KEY: &str = "a2a";

/// The A2A plane's accumulated fixture state, mutated across the fluent chain and consumed once by
/// [`finalize`] at build time.
#[derive(Default)]
pub(crate) struct A2aScratch {
    agent_defs: AgentsCfg,
    registered: bool,
}

fn scratch(app: &mut TestApp) -> &mut A2aScratch {
    let needs_register = !app.plane_scratch::<A2aScratch>(SCRATCH_KEY).registered;
    if needs_register {
        app.plane_scratch::<A2aScratch>(SCRATCH_KEY).registered = true;
        app.register_plane_finalizer(Box::new(finalize));
    }
    app.plane_scratch::<A2aScratch>(SCRATCH_KEY)
}

/// BUILD-TIME FINALIZER: consume the accumulated [`A2aScratch`] and install the real A2A plane through
/// core's neutral seams. Mirrors what busbar-core's `TestApp::build`/`build_a2a_plane_runtime` did.
fn finalize(app: &mut TestApp) {
    // Register this plane in the process registry the way production's composition root does.
    busbar_core::plane::registry::register_test_plane(&crate::PLANE_DECL);
    let scratch = app.take_plane_scratch::<A2aScratch>(SCRATCH_KEY);

    // Always carry the type-erased `agents:` handle onto the App (production fidelity; no test-path
    // consumer downcasts it — the plane reads its `AgentsCfg` off its runtime object).
    app.set_agent_defs_any(Arc::new(scratch.agent_defs.clone()));

    // The per-agent hook SPECS as neutral strings — core resolves the gates like production does.
    let containers: Vec<(String, Vec<String>)> = scratch
        .agent_defs
        .agents
        .iter()
        .map(|(n, d)| (n.clone(), d.hooks.clone()))
        .collect();
    app.set_a2a_container_hooks(containers, scratch.agent_defs.all_agent_hooks.clone());

    // THE A2A RUNTIME, when a receiving side is configured. MIRROR production's `a2a_start` hook:
    // stamp busbar's PUBLIC card-issuer key (off governance, via the neutral getter) onto the plane.
    if let Some(plane) = A2aPlane::from_config(&scratch.agent_defs, app.configured_public_url()) {
        if let Some(issuer) = app.a2a_card_issuer() {
            plane.set_card_issuer(issuer);
        }
        let admission = plane.admission();
        app.install_plane_runtime(crate::PLANE_DECL.key, plane);
        // Mount the JSON-RPC front door AND the gRPC path (a claimed path is where the RFC 8707
        // audience is found), and wire the admission when the plane claims/admits anything.
        app.mount_plane(
            crate::PLANE_DECL.key,
            crate::a2a::serve::MOUNT_PATH,
            busbar_core::plane::WIRE_JSONRPC,
        );
        app.mount_plane(
            crate::PLANE_DECL.key,
            crate::a2a::serve::GRPC_MOUNT_PATH,
            busbar_core::plane::WIRE_GRPC,
        );
        if let Some(admission) = admission {
            app.admit_plane(crate::PLANE_DECL.key, admission);
        }
    }
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

impl TestAppA2aExt for TestApp {
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
