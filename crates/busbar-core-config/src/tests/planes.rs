// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT FOR THIS CRATE'S OWN TEST BINARY — the one file in `busbar-core-config` that
//! names a plane crate, and it names each of them exactly once.
//!
//! A config test that writes `pools:`, `tools:`, `agents:`, a `providers:` entry or a bare hook
//! reference is exercising a grammar the PLUGINS declare: which sections exist, which plane parses
//! one, which protocols a provider may name, what noun an operator reads back in a refusal. A
//! shipped binary answers those questions because its composition root installed the planes and the
//! dialects before any config was read. A test binary has no composition root, so this file is it —
//! and it does the job the way `crates/busbar/src/main.rs` does, by calling each plugin's own
//! `install_test_seams`, which registers through the neutral substrate seams and nothing else.
//!
//! It lives under `tests/` on purpose: that path is off the source the kind-isolation and
//! plane-purity lints scan for PRODUCTION reach, so this crate's production source keeps naming no
//! plane crate and no dialect, which is the property the whole config-home cut exists to establish.
//!
//! ORDER IS THE POINT of doing it here rather than per test. The registration order IS the canonical
//! layering order (the registry derives the order from its data, and this binary has no built-in
//! rows), so `[llm, mcp, a2a]` here is what makes `config_sections()` report the sections in the
//! order an operator sees them from a real binary. `Once`-guarded and driven off every forward in
//! `crate::planes`, so the registry is populated before the first read no matter which test runs
//! first.

/// Install the shipped plugin set for this test binary, once, in layering order.
pub(crate) fn ensure() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // FIRST, and first for a reason: this plugin owns `pools:` — the section this crate's own
        // grammar splits and the one the fallback plane is resolved through — and it also registers
        // the shipped DIALECTS, which the validator refuses a `providers:` entry without.
        busbar_llm::testkit::install_test_seams();
        busbar_mcp::testkit::install_test_seams();
        busbar_a2a::testkit::install_test_seams();
        // The section list a cross-plane hook refusal is judged against is a PROVIDER on the neutral
        // seam; bind this crate's own fold so a plugin's parse-time refusal sees the same list the
        // document's own validator does, exactly as the composition root binds it at boot.
        busbar_substrate::plane::config::install_plane_sections(
            busbar_substrate::plane::config::config_sections,
        );
    });
}
