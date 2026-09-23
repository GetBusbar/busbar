// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The composition root hand-writes the decision plane's declaration, so these are the checks that
//! nothing else in the tree can make: that the hand-written identity is the plane's own, that the
//! section it claims is claimable, and that what it installs is inert.

use busbar_contract::plane::PlaneMeta;
use busbar_kernel::plane::registry::{
    check_owned_config_claims, merged_boot_plane_decls, CORE_OWNED_CONCRETE_SECTIONS,
};
use busbar_plane_decision::DecisionPlane;

use super::{CONFIG_SECTION, PLANE_DECL};

/// THE DRIFT THIS FILE EXISTS FOR. The registry key is written in the root and the plane answers to
/// its own `PlaneMeta::KEY`; if the two ever stop being one value, the process registers one name
/// and the plane is another, and nothing else in the tree compares them.
#[test]
fn the_declared_key_is_the_plane_s_own() {
    assert_eq!(PLANE_DECL.key, <DecisionPlane as PlaneMeta>::KEY);
    assert_eq!(PLANE_DECL.key, "decision");
}

/// The declaring SECTION is the operator's plural noun and is deliberately not the key — the same
/// split `mcp`/`tools` and `voice`/`streams` already have.
#[test]
fn the_section_is_the_operator_s_noun_and_not_the_key() {
    assert_eq!(PLANE_DECL.config_section, CONFIG_SECTION);
    assert_eq!(CONFIG_SECTION, "decisions");
    assert_ne!(PLANE_DECL.config_section, PLANE_DECL.key);
}

/// THE SECTION IS CLAIMABLE. `decisions:` was never a concrete `DeployCfg` field, so claiming it
/// evicts nothing from core and the dup-claim guard admits it. A claim on a core-owned section
/// would be a boot PANIC out of `merged_boot_plane_decls`, which is why this is asserted against
/// the real reserved list rather than a copy of it.
#[test]
fn the_claimed_section_is_not_one_core_still_owns() {
    assert_eq!(PLANE_DECL.owned_config_sections, &[CONFIG_SECTION]);
    assert!(
        !CORE_OWNED_CONCRETE_SECTIONS.contains(&CONFIG_SECTION),
        "core still owns `{CONFIG_SECTION}` concretely — a plane may only claim a section in the \
         same change that evicts it"
    );
    check_owned_config_claims(&[&PLANE_DECL], CORE_OWNED_CONCRETE_SECTIONS)
        .expect("the decision plane's own claim must pass the dup-claim guard alone");
}

/// REGISTRATION IS WHAT PUTS `decisions:` IN FRONT OF EVERY READER. The section fold is what
/// cross-plane hook references are judged against, and it is a fold over the installed decls'
/// `config_section` — so this drives the fold itself rather than asserting on the field it reads.
#[test]
fn registering_this_decl_puts_decisions_into_the_section_fold() {
    let sections = busbar_kernel::plane::config::config_sections_from(&[&PLANE_DECL]);
    assert!(
        sections.contains(&CONFIG_SECTION),
        "the fold over the installed decls does not report `{CONFIG_SECTION}`: {sections:?}"
    );
}

/// THE FOLD KEEPS IT. `merged_boot_plane_decls` dedups by key and normalises to canonical layering
/// order, and a plane outside the canonical set sorts to the tail — it must not be DROPPED there.
#[test]
fn the_boot_fold_keeps_the_decision_plane() {
    let folded = merged_boot_plane_decls(&[&PLANE_DECL], &[]);
    assert!(
        folded.iter().any(|d| d.key == PLANE_DECL.key),
        "the boot fold dropped the decision plane"
    );
}

/// IDENTITY ONLY. Installing this declaration must mount no route, bind no audience and contribute
/// no runtime slot — the plane has no unit path in `root/` to answer from yet, and a mounted door
/// with nothing behind it is the one shape the admission ratchets exist to refuse.
#[test]
fn the_declaration_mounts_nothing_and_admits_nobody() {
    let nothing: &dyn std::any::Any = &();
    assert!((PLANE_DECL.claims)(nothing).is_empty());
    assert!((PLANE_DECL.admission)(nothing).is_none());
    assert!(PLANE_DECL.routes.is_none());
    assert!(PLANE_DECL.admin_routes.is_none());
    assert!(PLANE_DECL.hydrate.is_none());
    assert!(PLANE_DECL.start.is_none());
    assert!(
        !PLANE_DECL.fallback,
        "the fallback catch-all is the LLM plane's flag and exactly one plane sets it"
    );
}

/// ONE WIRE FORMAT, so the plane earns no superset IR. jev names its operation in the request line,
/// not in a body member, and there is no second dialect to meet a first one in.
#[test]
fn the_plane_declares_the_one_wire_format_jev_speaks() {
    assert_eq!(
        (PLANE_DECL.wire_format_names)(),
        &[busbar_kernel::plane::WIRE_HTTP_JSON]
    );
}
