// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `NamedMapSection::sections(doors)` BYTE-IDENTITY TEST, relocated here from
//! `src/config/tests/named_map_tests.rs` (the "fix the 38" pass after the A6/HostCtx
//! dev-dependency-cycle cleanup): `sections(doors)` is folded from the REAL plane roster of the lent door table (see
//! its doc — under the default/test/openapi feature set the fold is `[identity-providers, export,
//! tools, agents]`, where `"tools"` is a linked plane's own declared config section and
//! `"agents"` the section the roster's DOOR row states — a `door:` row of the test-linked list,
//! the plane's own door folded from its Statement by the kernel's door fold and registered in the
//! list's (layering) order, as the composition root folds it in a shipped build). Pinning
//! that frozen order is a claim about the roster's fold, which
//! `cargo xtask gate construction`'s `neutral-no-dialect` rule (ceiling 0) forbids `busbar-kernel`
//! itself from asserting via a synthetic `#[cfg(test)]` decl. Every other test in
//! `named_map_tests.rs` is parameterized over WHATEVER `NamedMapSection::sections(doors)` returns and
//! stays there.

mod linked;

use busbar_kernel::config::named_map::NamedMapSection;

fn register_planes() {
    linked::install();
}

/// F2 — BYTE-IDENTITY PIN. `sections(doors)` is folded from the lent door table, so its ORDER is what the
/// router mounts and the OpenAPI generator emits in. Under the default/test/openapi-generating
/// build's set of registered planes it MUST equal the frozen 1.5.3 order
/// `[identity-providers, export, tools, agents]` — anything else drifts `openapi.json`. The session
/// plane's section is SINGULAR (no `named_def_list`), so it never joins this named-map list.
#[test]
fn sections_holds_the_frozen_named_map_order_under_the_default_feature_set() {
    register_planes();
    let keys: Vec<&'static str> = NamedMapSection::sections(linked::table())
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
