// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-LINKED PLANES — how a cross-plane integration test gets real planes without naming one.
//!
//! "A plugin tests itself; the kernel never tests or names a plugin" (the instance-noun-neutrality
//! header). These tests still need real planes registered, because what they prove is the kernel's
//! behaviour against whatever planes a build links. So WHICH planes is data: the crate list in
//! `[package.metadata.busbar] test-linked` (Cargo.toml), turned by `build.rs` into
//! `$OUT_DIR/test_linked.rs` — one `testkit::TEST_SEAM` entry per linked crate — and included here.
//!
//! A test then ADDRESSES a plane by what the plane declares about itself, read back from the
//! registry: the config section it owns ([`owning`]), the fallback flag ([`fallback`]), or any
//! other declared fact ([`declaring`]). It spells no plane key, no crate identifier and no literal
//! that is one; the key, section and mount path it uses are the declaration's own values.
//!
//! A lookup that no linked plane answers REFUSES, naming what was asked for and where the list
//! lives — a test addressed at a plane that is not test-linked fails loudly, never passes vacuously
//! over an empty roster (`tests/linked_roster.rs` holds that arm).

#![allow(dead_code)]

use busbar_kernel::plane::registry::{plane_decls, PlaneDecl};
use busbar_kernel::test_support::seam::{
    register_test_plane_seam, test_plane_seams, TestPlaneSeam,
};

include!(concat!(env!("OUT_DIR"), "/test_linked.rs"));

/// Install every test-linked plane exactly as the composition root installs it in production
/// (protocol declarations, plane row, ingress seams). Idempotent: each entry's own install is
/// first-wins, and the registration loop runs once per test binary.
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for entry in TEST_LINKED {
            register_test_plane_seam(entry);
        }
    });
    for seam in test_plane_seams() {
        (seam.install)();
    }
}

/// How many plane crates this test binary links (the length of the Cargo.toml list).
pub fn linked_count() -> usize {
    TEST_LINKED.len()
}

/// The registered plane list after [`install`], in registration order.
pub fn planes() -> &'static [&'static PlaneDecl] {
    install();
    plane_decls()
}

/// The ONE linked plane whose declaration satisfies `pred`. Refuses — naming `what` and the
/// manifest list — when none does, and when more than one does (an address must be unambiguous).
pub fn declaring(what: &str, pred: impl Fn(&PlaneDecl) -> bool) -> &'static PlaneDecl {
    let hits: Vec<&'static PlaneDecl> = planes().iter().copied().filter(|d| pred(d)).collect();
    match hits.as_slice() {
        [one] => one,
        [] => panic!(
            "no test-linked plane declares {what}: the planes this test binary links are the \
             crates listed in `[package.metadata.busbar] test-linked` (crates/busbar-kernel/\
             Cargo.toml); registered keys: {:?}",
            planes().iter().map(|d| d.key).collect::<Vec<_>>()
        ),
        many => panic!(
            "{} test-linked planes declare {what} ({:?}); an address must name exactly one",
            many.len(),
            many.iter().map(|d| d.key).collect::<Vec<_>>()
        ),
    }
}

/// The linked plane that owns top-level config section `section` — the section that declares it,
/// or one of the sections whose grammar it declares it owns.
pub fn owning(section: &str) -> &'static PlaneDecl {
    declaring(&format!("the `{section}:` config section"), |d| {
        d.config_section == section || d.owned_config_sections.contains(&section)
    })
}

/// The linked plane that declares itself the FALLBACK catch-all.
pub fn fallback() -> &'static PlaneDecl {
    declaring("itself the fallback plane", |d| d.fallback)
}

/// The top-level section that is `decl`'s endpoint door: the first section whose grammar it declares
/// it owns, else the section that declares it.
pub fn door_section(decl: &PlaneDecl) -> &'static str {
    decl.owned_config_sections
        .first()
        .copied()
        .unwrap_or(decl.config_section)
}

/// `decl`'s own test-seam entry — what its test kit exports for a cross-plane test to drive it by
/// (its served-call framer, its carried verify-gate reader), found by the key it declares.
pub fn seam(decl: &PlaneDecl) -> &'static TestPlaneSeam {
    install();
    test_plane_seams()
        .into_iter()
        .find(|s| s.name == decl.key)
        .unwrap_or_else(|| panic!("the `{}` plane registered no test seam", decl.key))
}
