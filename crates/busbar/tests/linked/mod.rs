// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-LINKED PLANES — how a cross-plane integration test gets real planes without naming one.
//!
//! These tests prove the kernel's behaviour against whatever planes a build links, so they live in
//! the composition root, where a plane may be linked: core names zero plane types, its tests
//! included. WHICH planes is data: the crate list in `[package.metadata.busbar.test-linked] planes`
//! (crates/busbar/Cargo.toml), turned by `build.rs` into `$OUT_DIR/test_linked.rs` — one
//! `testkit::TEST_SEAM` entry per linked crate, and one `plane_door::door` per `door:` row (a plane
//! served through its memory-ABI door only, whose row is folded from its Statement as the
//! composition root folds it) — and included here.
//!
//! The binary's DOOR TABLE ([`table`]) is the one the composition root would fold over those rows
//! and lend: a test reads every plane fact off it, and lends it to the `App` it builds
//! (`TestApp::doors`) and to every config parse it runs, as the root lends its own.
//!
//! A test then ADDRESSES a plane by what the plane declares about itself, read back from that
//! table: the config section it owns ([`owning`]), the fallback flag ([`fallback`]), or any
//! other declared fact ([`declaring`]). It spells no plane key, no crate identifier and no literal
//! that is one; the key, section and mount path it uses are the declaration's own values.
//!
//! A lookup that no linked plane answers REFUSES, naming what was asked for and where the list
//! lives — a test addressed at a plane that is not test-linked fails loudly, never passes vacuously
//! over an empty roster.

#![allow(dead_code)]

use busbar_kernel::plane_driver::doors::Doors;
use busbar_kernel::plane_driver::row::PlaneDecl;
use busbar_kernel::test_support::seam::{
    register_test_plane_seam, test_plane_seams, TestPlaneSeam,
};

include!(concat!(env!("OUT_DIR"), "/test_linked.rs"));

/// The test-linked fallback plane's door registration: the one `door:` row whose Statement tail
/// flags it the fallback (`TAIL_FALLBACK`), bound through the loader's one load as the composition
/// root binds it. The kernel holds no protocol set (a plane resolves its own dialects, spec Part 1,
/// Law 5); a test that needs a dialect reads it here, off the plane's door (BUSBAR-1.6.0.md
/// l.4965: kernel and root users go via the plane ABI).
/// Bound once per test binary.
pub fn fallback_registration() -> &'static busbar_contract::plane_calls::PlaneRegistration {
    use busbar_plugin_loader::dispatch::kinds::plane::{linked_probe, registration};
    static REG: std::sync::OnceLock<busbar_contract::plane_calls::PlaneRegistration> =
        std::sync::OnceLock::new();
    REG.get_or_init(|| {
        let mut fallbacks: Vec<_> = TEST_LINKED_DOORS
            .iter()
            .map(|&(label, door)| {
                registration(linked_probe(door, label))
                    .unwrap_or_else(|e| panic!("the test-linked door `{label}` binds: {e}"))
            })
            .filter(|reg| reg.fallback)
            .collect();
        assert_eq!(
            fallbacks.len(),
            1,
            "one test-linked door is the fallback plane (`[package.metadata.busbar.test-linked] \
             planes`)"
        );
        fallbacks.remove(0)
    })
}

/// The fallback door's dialects, in its Statement tail's order.
pub fn fallback_dialects() -> Vec<&'static str> {
    fallback_registration().dialects.clone()
}

/// The fallback door's operation classes, in its Statement tail's order: the verbs its units are
/// priced and labelled by.
pub fn fallback_op_classes() -> Vec<&'static str> {
    use busbar_plugin_loader::dispatch::kinds::plane::linked_probe;
    TEST_LINKED_DOORS
        .iter()
        .map(|&(label, door)| {
            linked_probe(door, label)()
                .unwrap_or_else(|e| panic!("the test-linked door `{label}` binds: {e}"))
                .served()
        })
        .find(|served| served.fallback)
        .map(|served| served.op_classes)
        .expect("one test-linked door is the fallback plane")
}

/// The dialect the fallback door's catch-all claim wears (its claim on `/`, the previous release's
/// fallback; BUSBAR-1.6.0.md l.909: each plane declares its claims per dialect): the name a fixture
/// lane or provider uses where any provider dialect will do.
pub fn residual_default_dialect() -> &'static str {
    static DIALECT: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    DIALECT.get_or_init(|| {
        let facing = (fallback_registration().facing)(b"{}", b"", None, &[])
            .unwrap_or_else(|e| panic!("the fallback door faces the world: {e}"));
        facing
            .claims
            .into_iter()
            .find(|(target, _)| target == "/")
            .map(|(_, dialect)| dialect)
            .expect("the fallback door claims `/` for a dialect")
    })
}

/// The dialect the fallback door's claim on exactly `path` wears, read off its facing claims
/// (BUSBAR-1.6.0.md l.909: each plane declares its claims per dialect): a test's way to name a
/// dialect a linked plane states without spelling one, as `root::linked::dialect_for_path` is the
/// root's own tests'.
pub fn dialect_for_path(path: &str) -> Option<&'static str> {
    let facing = (fallback_registration().facing)(b"{}", b"", None, &[])
        .unwrap_or_else(|e| panic!("the fallback door faces the world: {e}"));
    facing
        .claims
        .into_iter()
        .find(|(target, _)| target == path)
        .map(|(_, dialect)| dialect)
}

/// Install every test-linked plane's seams exactly as the composition root installs them in
/// production (ingress seams), in the list's order, which is the planes' layering order. A door
/// plane installs nothing: its row is folded into the binary's door table ([`table`]), which a test
/// is lent rather than finding installed. Idempotent: each entry's own install is first-wins, and the
/// seam registration loop runs once per test binary.
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for entry in TEST_LINKED {
            register_test_plane_seam(entry);
        }
    });
    for entry in TEST_LINKED {
        (entry.install)();
    }
    for seam in test_plane_seams() {
        (seam.install)();
    }
}

/// THIS TEST BINARY'S DOOR TABLE: every test-linked door plane's row, in the list's order (the
/// planes' layering order), folded as the composition root folds its own (`Doors::for_test`: one
/// row per key, layering order, every owned-config claim checked). Folded once per test binary; a
/// test reads every plane fact off it and lends it to what it drives. Installs the seams first
/// ([`install`]), so a test that reads the table drives the planes the root would have installed.
pub fn table() -> Doors {
    static TABLE: std::sync::OnceLock<Doors> = std::sync::OnceLock::new();
    install();
    *TABLE.get_or_init(|| {
        let doors = door_rows();
        let mut rows: Vec<&'static PlaneDecl> = Vec::new();
        let mut door = 0;
        for &is_door in TEST_LINKED_ORDER {
            if is_door {
                rows.push(doors[door]);
                door += 1;
            }
        }
        Doors::for_test(&rows)
    })
}

/// The kernel's one-provider fixture configuration (`test_support::cfg_with_provider_api_key`) LENT
/// `doors`, as the composition root lends its table to the configuration it parses: its provider
/// names the first dialect `doors` declares, so the boot accepts it (the neutral plane's dialect
/// when `doors` declares none). The kernel names no dialect; the table states it.
pub fn cfg_lent(
    doors: Doors,
    api_key: busbar_kernel::config::SecretRef,
) -> busbar_kernel::config::RootCfg {
    let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(api_key);
    cfg.doors = doors;
    if let Some(dialect) = doors.provider_dialects().first().copied() {
        for provider in cfg.providers.values_mut() {
            provider.table.insert(
                busbar_contract::section::MODEL_PROTOCOL_KEYS[0].to_string(),
                serde_json::Value::from(dialect),
            );
        }
    }
    cfg
}

/// Every test-linked door plane's registry row, folded once per test binary.
fn door_rows() -> &'static [&'static PlaneDecl] {
    static ROWS: std::sync::OnceLock<Vec<&'static PlaneDecl>> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        TEST_LINKED_DOORS
            .iter()
            .map(|&(label, door)| fold_door(label, door))
            .collect()
    })
}

/// A door plane's registry row: a probe of the door bound through the loader's one load
/// (`linked_probe`), its facts read as a registration and folded by the kernel
/// (`plane_driver::door::fold`) — the path the composition root folds every door candidate by
/// (`root::linked::door_rows`).
fn fold_door(
    label: &str,
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> &'static PlaneDecl {
    use busbar_plugin_loader::dispatch::kinds::plane::{linked_probe, registration};
    let reg = registration(linked_probe(door, label))
        .unwrap_or_else(|e| panic!("the test-linked door `{label}` binds: {e}"));
    busbar_kernel::plane_driver::door::fold(reg)
        .unwrap_or_else(|e| panic!("the test-linked door `{label}` folds: {e}"))
}

/// How many plane crates this test binary links (the length of the Cargo.toml list: the linked
/// planes and the door planes).
pub fn linked_count() -> usize {
    TEST_LINKED.len() + TEST_LINKED_DOORS.len()
}

/// The rows of this binary's door table ([`table`]), in its fold order.
pub fn planes() -> &'static [&'static PlaneDecl] {
    table().decls()
}

/// The ONE linked plane whose declaration satisfies `pred`. Refuses — naming `what` and the
/// manifest list — when none does, and when more than one does (an address must be unambiguous).
pub fn declaring(what: &str, pred: impl Fn(&PlaneDecl) -> bool) -> &'static PlaneDecl {
    let hits: Vec<&'static PlaneDecl> = planes().iter().copied().filter(|d| pred(d)).collect();
    match hits.as_slice() {
        [one] => one,
        [] => panic!(
            "no test-linked plane declares {what}: the planes this test binary links are the \
             crates listed in `[package.metadata.busbar.test-linked] planes` (crates/busbar/\
             Cargo.toml); the table's keys: {:?}",
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

/// Every test-linked door plane's door, by its crate's label.
pub fn doors() -> &'static [(&'static str, busbar_contract::abi::mechanism::door::DoorFn)] {
    TEST_LINKED_DOORS
}
