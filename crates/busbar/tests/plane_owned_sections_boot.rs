// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! M5 — A PLANE THAT OWNS A TOP-LEVEL SECTION BOOTS WITH IT. For every plane the composition root
//! links from its own crate (build.rs: the `[package.metadata.busbar.linked]` rows carrying the
//! `plane` axis) that DECLARES sections it owns the grammar of: its section hooks are wired, the
//! dup-claim guard admits the real roster and refuses a planted rival, registering the plane puts the
//! section into the config grammar, and no plane may claim a core-owned section.
//!
//! The planes are addressed by what they declare, read off the linked rows; the source names none.
//! The exact owned sections of today's roster are pinned as data in `tests/fixtures/plane_doctrine.txt`
//! (`owned-section` rows) and compared when every plane is compiled in.
#![cfg(linked_axis_plane)]

mod common;

use busbar_kernel::plane::registry::{
    check_owned_config_claims, register_test_plane, PlaneDecl, CORE_OWNED_CONCRETE_SECTIONS,
};

// `CORE_OWNED_CONCRETE_SECTIONS` is the kernel's REAL list — the one the boot guard judges against —
// imported rather than mirrored (item 267: a mirror is a second list that can drift from the first).

include!(concat!(env!("OUT_DIR"), "/linked_planes.rs"));

/// The linked planes that declare sections they own the grammar of.
fn owning_planes() -> Vec<&'static PlaneDecl> {
    let owning: Vec<&'static PlaneDecl> = LINKED_PLANES
        .iter()
        .filter(|d| !d.owned_config_sections.is_empty())
        .collect();
    #[cfg(linked_every_plane)]
    assert!(
        !owning.is_empty(),
        "non-vacuity: with every plane compiled in, some linked plane owns a section"
    );
    owning
}

/// Each owning plane WIRES the two seam hooks that let `DeployCfg` deserialize/validate its owned
/// section without naming a plane type: it PARSES the section, and an ABSENT section defaults.
#[test]
fn every_owning_plane_wires_the_section_hooks() {
    for d in owning_planes() {
        assert!(
            d.parse_section.is_some(),
            "`{}` must PARSE its owned {:?} section (parse_section wired)",
            d.key,
            d.owned_config_sections
        );
        assert!(
            d.default_section.is_some(),
            "an ABSENT {:?} section of `{}` must default (default_section wired)",
            d.owned_config_sections,
            d.key
        );
    }
}

/// With every plane compiled in, the owning planes and their sections are EXACTLY the pinned ones:
/// `owned-section <plane key> <declaring section> <owned section>...` rows of the doctrine fixture.
#[cfg(linked_every_plane)]
#[test]
fn the_owned_sections_are_the_pinned_ones() {
    let live: std::collections::BTreeSet<Vec<&str>> = owning_planes()
        .iter()
        .map(|d| {
            let mut row = vec![d.key, d.config_section];
            row.extend(d.owned_config_sections.iter().copied());
            row
        })
        .collect();
    let pinned: std::collections::BTreeSet<Vec<&str>> =
        common::doctrine_rows("owned-section").into_iter().collect();
    assert_eq!(
        live, pinned,
        "the linked planes' owned sections are the doctrine's; a section changing owner is a \
         config-grammar change, not a refactor"
    );
}

/// The dup-claim guard ADMITS the real roster: no owned section is core-owned and each has one
/// claimant. (The collision-refusal half against a synthetic second claimant is below.)
#[test]
fn dup_claim_guard_admits_the_real_roster() {
    let roster: Vec<&busbar_contract::plane::PlaneDeclaration> =
        LINKED_PLANES.iter().map(|d| &d.declaration).collect();
    check_owned_config_claims(&roster, CORE_OWNED_CONCRETE_SECTIONS).expect(
        "each owned section is claimed once and none is core-owned — the real roster is admitted",
    );
}

/// The dup-claim guard REFUSES a planted collision: a SECOND plane built by functional update off a
/// REAL owning decl (every field but `key` copied, so it claims exactly what that plane claims) is a
/// hard error naming the contested section and both claimants — for every owning plane.
#[test]
fn dup_claim_guard_refuses_a_planted_collision() {
    for d in owning_planes() {
        let rival_key: &'static str = Box::leak(format!("rival-{}", d.key).into_boxed_str());
        let rival: &'static busbar_contract::plane::PlaneDeclaration =
            Box::leak(Box::new(busbar_contract::plane::PlaneDeclaration {
                key: rival_key,
                ..d.declaration
            }));
        let err = check_owned_config_claims(&[&d.declaration, rival], CORE_OWNED_CONCRETE_SECTIONS)
            .expect_err(
                "two planes claiming one section MUST be refused — one plane's grammar would \
                 answer for the other's",
            );
        let section = d.owned_config_sections[0];
        assert!(
            err.contains(section) && err.contains(d.key) && err.contains(rival_key),
            "the refusal must name the contested section and both claimants, got: {err}"
        );
    }
}

/// Registering an owning plane puts its section into the config-grammar section list
/// `config_sections()` reports — the list the cross-plane hook-reference rule (and every reader that
/// asks "what top-level sections exist") judges against. The list carries each registered plane's
/// DECLARING section (`config_section`), which for a plane whose one owned section declares it is
/// that owned section.
#[test]
fn registering_an_owning_plane_puts_its_section_into_config_sections() {
    for d in owning_planes() {
        register_test_plane(d);
    }
    let sections = busbar_kernel::plane::config::config_sections();
    for d in owning_planes() {
        assert!(
            sections.contains(&d.config_section),
            "`{}`'s `{}:` section must reach the config grammar once the plane is registered, \
             got: {sections:?}",
            d.key,
            d.config_section
        );
    }
}

/// Every section core owns is REFUSED to a plane that claims it — asked of the kernel's own list, so
/// a section added to (or evicted from) it is judged here the day it moves, with no copy to update.
/// The real owning planes are the admitted control: the refusal is about the section, not the plane.
#[test]
fn a_plane_claiming_any_real_core_owned_section_is_refused() {
    assert!(
        !CORE_OWNED_CONCRETE_SECTIONS.is_empty(),
        "non-vacuity: core owns concrete sections, and this test must be asked of them"
    );
    for d in owning_planes() {
        for owned in d.owned_config_sections {
            assert!(
                !CORE_OWNED_CONCRETE_SECTIONS.contains(owned),
                "`{}`'s `{owned}:` is not core-owned; the admitted control depends on it",
                d.key
            );
        }
        for section in CORE_OWNED_CONCRETE_SECTIONS {
            let owned: &'static [&'static str] = Box::leak(Box::new([*section]));
            let grabber = busbar_contract::plane::PlaneDeclaration {
                key: "section-grabber",
                owned_config_sections: owned,
                ..d.declaration
            };
            let err = check_owned_config_claims(&[&grabber], CORE_OWNED_CONCRETE_SECTIONS)
                .expect_err("a plane claiming a core-owned section must be refused");
            assert!(
                err.contains(section),
                "the refusal must name the core-owned section `{section}`, got: {err}"
            );
        }
    }
}
