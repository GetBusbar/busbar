// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `NamedMapSection::sections()` BYTE-IDENTITY TEST, relocated here from
//! `src/config/tests/named_map_tests.rs` (the "fix the 38" pass after the A6/HostCtx
//! dev-dependency-cycle cleanup): `sections()` is folded from the REAL registered plane roster (see
//! its doc — under the default/test/openapi feature set the fold is `[identity-providers, export,
//! tools, agents]`, where `"tools"`/`"agents"` are the REAL `busbar_mcp`/`busbar_a2a` planes' own
//! declared config sections). Pinning that frozen order is a claim about the real roster, which
//! `cargo xtask gate construction`'s `neutral-no-dialect` rule (ceiling 0) forbids `busbar-kernel`
//! itself from asserting via a synthetic `#[cfg(test)]` decl. Every other test in
//! `named_map_tests.rs` is parameterized over WHATEVER `NamedMapSection::sections()` returns and
//! stays there.

mod linked;

use busbar_kernel::config::named_map::NamedMapSection;

fn register_planes() {
    linked::install();
}

/// F2 — BYTE-IDENTITY PIN. `sections()` is folded from the plane registry, so its ORDER is what the
/// router mounts and the OpenAPI generator emits in. Under the default/test/openapi-generating
/// build's set of registered planes it MUST equal the frozen 1.5.3 order
/// `[identity-providers, export, tools, agents]` — anything else drifts `openapi.json`. `streams:`
/// is a SINGULAR plane section (no `named_def_list`), so it never joins this named-map list.
#[test]
fn sections_holds_the_frozen_named_map_order_under_the_default_feature_set() {
    register_planes();
    let keys: Vec<&'static str> = NamedMapSection::sections()
        .iter()
        .map(|s| s.key())
        .collect();
    assert_eq!(
        keys,
        vec!["identity-providers", "export", "tools", "agents"],
        "sections() must yield the frozen 1.5.3 order so the router/OpenAPI surface stays \
         byte-identical"
    );
}
