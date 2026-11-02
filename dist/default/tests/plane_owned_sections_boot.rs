// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(linked_axis_plane_door)]

mod linked;

use busbar_kernel::plane_driver::registry::{
    check_owned_config_claims, PlaneDecl, CORE_OWNED_CONCRETE_SECTIONS,
};

fn linked_planes() -> &'static [&'static PlaneDecl] {
    linked::planes()
}

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

#[test]
fn dup_claim_guard_admits_the_real_roster() {
    let roster: Vec<&busbar_contract::plane::PlaneDeclaration> =
        linked_planes().iter().map(|d| &d.declaration).collect();
    check_owned_config_claims(&roster, CORE_OWNED_CONCRETE_SECTIONS).expect(
        "each owned section is claimed once and none is core-owned — the real roster is admitted",
    );
}

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

#[test]
fn registering_an_owning_plane_puts_its_section_into_config_sections() {
    linked::install();
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
