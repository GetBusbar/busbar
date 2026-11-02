// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Linked plane doors expose their owned sections to configuration parsing. The real roster must
//! register those sections and refuse duplicate ownership or claims on core-owned sections.
#![cfg(linked_axis_plane_door)]

mod common;

use busbar_kernel::plane_driver::registry::{
    check_owned_config_claims, PlaneDecl, CORE_OWNED_CONCRETE_SECTIONS,
};
use busbar_kernel_testkit::test_support::planes::register_test_plane;

// `CORE_OWNED_CONCRETE_SECTIONS` is the kernel's REAL list — the one the boot guard judges against —
// imported rather than mirrored (item 267: a mirror is a second list that can drift from the first).

include!(concat!(env!("OUT_DIR"), "/linked_plane_doors.rs"));

fn linked_planes() -> &'static [&'static PlaneDecl] {
    static PLANES: std::sync::OnceLock<Vec<&'static PlaneDecl>> = std::sync::OnceLock::new();
    PLANES.get_or_init(|| {
        LINKED_PLANE_DOORS
            .iter()
            .map(|door| {
                let candidate = busbar_plugin_loader::boot::Candidate::linked(*door)
                    .expect("the linked plane states a valid declaration");
                let registration =
                    busbar_plugin_loader::dispatch::kinds::plane::stated_registration(
                        &candidate,
                        std::sync::Arc::new(|| {
                            Err("declaration inspection does not bind a plane".into())
                        }),
                    )
                    .expect("the linked plane states its registration without binding");
                busbar_kernel::plane_driver::door::fold(registration)
                    .expect("the door declaration folds into a registry row")
            })
            .collect()
    })
}

/// The linked planes that declare sections they own the grammar of.
fn owning_planes() -> Vec<&'static PlaneDecl> {
    let owning: Vec<&'static PlaneDecl> = linked_planes()
        .iter()
        .copied()
        .filter(|d| !d.owned_config_sections.is_empty())
        .collect();
    #[cfg(linked_every_plane_door)]
    assert!(
        !owning.is_empty(),
        "the full distribution owns configuration sections"
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

/// No two linked planes own the same configuration section.
#[test]
fn the_owned_sections_have_distinct_owners() {
    let live: std::collections::BTreeSet<Vec<&str>> = owning_planes()
        .iter()
        .map(|d| {
            let mut row = vec![d.key, d.config_section];
            row.extend(d.owned_config_sections.iter().copied());
            row
        })
        .collect();
    let owned: Vec<&str> = live
        .iter()
        .flat_map(|row| row[2..].iter().copied())
        .collect();
    let distinct: std::collections::BTreeSet<&str> = owned.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        owned.len(),
        "each configuration section has one owning plane: {live:?}"
    );
}

/// The dup-claim guard ADMITS the real roster: no owned section is core-owned and each has one
/// claimant. (The collision-refusal half against a synthetic second claimant is below.)
#[test]
fn dup_claim_guard_admits_the_real_roster() {
    let roster: Vec<&busbar_contract::plane::PlaneDeclaration> =
        linked_planes().iter().map(|d| &d.declaration).collect();
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
    let sections = busbar_kernel::config::plane_sections::config_sections();
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
