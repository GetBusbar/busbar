// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLUGIN'S TEST-KIT — the composition-root-shaped install seam a `test-support` consumer
//! (busbar-core's own integration target, and any downstream test binary) uses to bring the LLM
//! protocol and plane into the process registries.
//!
//! It replaces the deleted `#[path]` witness re-includes of the six dialect sources into
//! `busbar-core`: `ProtocolDecl` and `PlaneDecl` now live in `busbar-substrate`, so a test registers
//! the REAL, externally-linked declarations through the neutral substrate seams — exactly as
//! production's composition root (`crates/busbar/src/main.rs`) hands [`crate::DECLS`] and
//! [`crate::PLANE_DECLARATION`] (joined kernel-side to [`crate::PLANE_HOOKS`]) to `install_protocols`/`install_planes`. `busbar-core`'s `test-support`
//! `registry()` folds the registered set ahead of its (empty) built-ins on every read, so a test that
//! installs these before it builds an `App` sees the same protocol set a shipped "busbar with the LLM
//! plane" binary has.

use busbar_kernel::{proto, test_support::seam::TestPlaneSeam};

/// THE SHELL, KEPT AS A WITNESS: the arrivals this plane answered with before every request on it
/// became a unit the composition root's node drives. See the module.
pub mod shell;

/// INSTALL THE LLM PROTOCOL + PLANE the composition root installs in production. Idempotent (both
/// underlying substrate registrations dedupe by name/key), so a test may call it freely — including
/// from several tests in one binary.
///
/// The arrivals are seeded through the neutral `set_test_path_ingress` / `set_test_body_ingress`
/// HOOKS (idempotent, first-writer-wins), NOT the set-once production installs — and what they are
/// seeded with is the SHELL'S ([`shell`]), not the loop's. A test binary that links this plane links
/// no composition root, so it has no node to hand a unit to; the shell answers it as it always did,
/// and a composition root's own tests read the loop against exactly that leg.
pub fn install_test_seams() {
    proto::register_test_protocols(crate::DECLS);
    busbar_kernel::plane::registry::register_test_plane(&PLANE_ROW);
    busbar_kernel::ingress::arrival::set_test_path_ingress(|| shell::PATH_INGRESS);
    busbar_kernel::ingress::arrival::set_test_body_ingress(|| shell::BODY_INGRESS);
    // The resolved-completion synthesizer (the MCP-sampling re-entry) — seeded through the neutral
    // `set_test_completion_ingress` HOOK, the test-support twin of the set-once production
    // `install_completion_ingress`, so a `test-support` consumer that drives a synthesized completion
    // resolves the LLM plane's synthesizer instead of the "no default chat protocol" error.
    busbar_kernel::ingress::arrival::set_test_completion_ingress(
        crate::native_ingress::synthesize_completion,
    );
    // The cross-protocol STREAMING translator factory. `busbar_kernel::proto::new_stream_translator`
    // routes through this installed pointer in a `test-support`/plugin test binary (where core's
    // `cfg(test)` is FALSE), so without it every cross-protocol streaming forward falls back to raw
    // passthrough — the exact composition-root write `main.rs::run` makes in production. Set-once.
    proto::install_stream_translator_factory(crate::proto_stream::new_stream_translator);
}

/// THIS PLANE'S LINKED-TEST-SEAM ENTRY — what a test binary that links this crate without naming it
/// registers into the kernel's test-seam registry and loops. No admin error surface.
pub const TEST_SEAM: TestPlaneSeam = TestPlaneSeam {
    name: "llm",
    install: install_test_seams,
    error_surface_driver: None,
    served_call: None,
    verify_gate: None,
};

/// This plane's registry row, assembled kernel-side from its contract declaration
/// and its behaviour table.
static PLANE_ROW: busbar_kernel::plane::registry::PlaneDecl =
    busbar_kernel::plane::registry::PlaneDecl::assemble(
        crate::PLANE_DECLARATION,
        crate::PLANE_HOOKS,
    );

// ── THE UNIT, FOR A NODE A TEST HOLDS ──────────────────────────────────────────────────────────────
//
// The loop's arrivals hand their unit to the ONE node the composition root installed. A composition
// root's own tests drive units on nodes of their own — one per deployment, at an arrival instant they
// choose — so the plane hands them the same unit its arrivals hand the node, built from the same one
// value that crosses per request, and the few plane facts a loop test reads its answer against.

/// What a path-model dialect's URL said, as the carry holds it.
pub use crate::arrival::PathModelFacts;
/// The native gate a test seats at Approve.
pub use crate::unit::approve::VetoSeat;
/// The one value that crosses from an arrival into the plane per unit.
pub use crate::unit::walk::WalkArrival;

/// ONE UNIT, exactly as this plane's arrivals hand it to the node — with the Approve seats the mount
/// installs ([`native_seats`]).
#[must_use]
pub fn handed(arrival: WalkArrival, model_hint: Option<String>) -> crate::unit::node::Handed {
    crate::unit::node::handed(arrival, model_hint, crate::unit::node::NATIVE_SEATS)
}

/// The same unit, judged at Approve by the seats named here rather than the mount's.
#[must_use]
pub fn handed_seated(
    arrival: WalkArrival,
    model_hint: Option<String>,
    seats: &'static [&'static (dyn VetoSeat + Sync)],
) -> crate::unit::node::Handed {
    crate::unit::node::handed(arrival, model_hint, seats)
}

/// THE SEATS THE MOUNT INSTALLS at Approve — empty on every deployment today.
#[must_use]
pub fn native_seats() -> &'static [&'static (dyn VetoSeat + Sync)] {
    crate::unit::node::NATIVE_SEATS
}

/// Whether `proto` declares NO handler for `operation` — the decode step's handler half, asked.
#[must_use]
pub fn declines(proto: &str, operation: busbar_contract::operation::OpVerb) -> bool {
    crate::unit::decode::handler_for(proto, operation).is_err()
}

/// The sentence the decode step's model ladder refuses a body naming no model with.
#[must_use]
pub fn missing_model_sentence() -> &'static str {
    crate::unit::decode::DecodeRefusal::MissingModel.message()
}

/// The sentence the decode step's handler half refuses an operation the dialect declines with.
#[must_use]
pub fn unsupported_operation_sentence() -> &'static str {
    crate::unit::decode::DecodeRefusal::UnsupportedOperation.message()
}

/// WHAT A UNIT'S CARRY SAYS ITS URL SAID: the model and the dialect's own miss copy, or `None` for a
/// unit whose model rides its body — read off the carry the unit is opened with.
#[must_use]
pub fn url_facts(arrival: WalkArrival) -> Option<(String, Option<String>)> {
    crate::unit::walk::Walk::open(arrival)
        .with_path(|facts| (facts.model.clone(), facts.model_not_found_message.clone()))
}
