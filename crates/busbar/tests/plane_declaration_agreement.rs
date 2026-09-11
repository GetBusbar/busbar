// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO HALVES OF A PLANE'S DECLARATION SAY THE SAME THING.
//!
//! A plane states its FACTS in its pure `busbar-plane-*` half, as contract data, and its BEHAVIOUR
//! in its engine, as the substrate's `PlaneDecl`. The engine row still CARRIES the ten data fields —
//! they are written and no longer read, and SUB-1 deletes them — so for exactly one landing the same
//! ten facts are spelt in two files. This is the test that stops that being a landing they drift in:
//! every field, every shipped plane, compared.
//!
//! IT LIVES IN THE ROOT because the root is the only crate that may name both halves of a plane.
//! That is the same reason `install_planes` takes them as a PAIR.
//!
//! WHEN THE FIELDS ARE DELETED, THIS FILE GOES WITH THEM: it is the guard on a duplication, not a
//! rule about planes, and a guard that outlives its duplication is a test that passes by tautology.

use busbar_contract::plane::PlaneDeclaration;
use busbar_substrate::plane::registry::PlaneDecl;

/// Every fact the declaration states, compared against the same fact on the behaviour row. Spelt out
/// field by field rather than through a conversion helper on purpose: a helper would be one more
/// place the two could agree to be wrong together, and the point of this test is that the two files
/// were written independently.
fn agree(what: &str, decl: &PlaneDeclaration, row: &PlaneDecl) {
    assert_eq!(decl.key, row.key, "{what}: key");
    assert_eq!(decl.fallback, row.fallback, "{what}: fallback");
    assert_eq!(
        decl.config_section, row.config_section,
        "{what}: config_section"
    );
    assert_eq!(decl.scope_kinds, row.scope_kinds, "{what}: scope_kinds");
    assert_eq!(decl.subject_noun, row.subject_noun, "{what}: subject_noun");
    assert_eq!(decl.admin_noun, row.admin_noun, "{what}: admin_noun");
    assert_eq!(decl.audit_kind, row.audit_kind, "{what}: audit_kind");
    assert_eq!(
        decl.card_signing_domain, row.card_signing_domain,
        "{what}: card_signing_domain"
    );
    assert_eq!(
        decl.card_kid_prefix, row.card_kid_prefix,
        "{what}: card_kid_prefix"
    );
    assert_eq!(
        decl.owned_config_sections, row.owned_config_sections,
        "{what}: owned_config_sections"
    );
}

#[cfg(feature = "proto-llm")]
#[test]
fn the_llm_plane_states_the_same_facts_in_both_halves() {
    agree(
        "llm",
        &busbar_plane_llm::meta::PLANE_DECLARATION,
        &busbar_llm::PLANE_DECL,
    );
}

#[cfg(feature = "plane-mcp")]
#[test]
fn the_mcp_plane_states_the_same_facts_in_both_halves() {
    agree(
        "mcp",
        &busbar_plane_mcp::meta::PLANE_DECLARATION,
        &busbar_mcp::PLANE_DECL,
    );
}

#[cfg(feature = "plane-a2a")]
#[test]
fn the_a2a_plane_states_the_same_facts_in_both_halves() {
    agree(
        "a2a",
        &busbar_plane_a2a::meta::PLANE_DECLARATION,
        &busbar_a2a::PLANE_DECL,
    );
}

#[cfg(feature = "plane-voice")]
#[test]
fn the_voice_plane_states_the_same_facts_in_both_halves() {
    agree(
        "voice",
        &busbar_plane_voice::meta::PLANE_DECLARATION,
        &busbar_voice::PLANE_DECL,
    );
}

/// A PLANE'S KEY IS ITS OWN, and the two tables are joined by it — so two planes sharing a key would
/// resolve one plane's facts onto another's hooks without anything failing. The composition root's
/// installer refuses a MISMATCHED pair; this refuses a DUPLICATED one, at the only place the whole
/// shipped set is visible.
#[test]
fn every_shipped_plane_declares_its_own_key() {
    let keys: Vec<&str> = SHIPPED.iter().map(|d| d.key).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        keys.len(),
        "two shipped planes declare the same key: {keys:?}"
    );
}

/// Every plane this build ships, by its pure half — the set the composition root installs.
const SHIPPED: &[&PlaneDeclaration] = &[
    #[cfg(feature = "proto-llm")]
    &busbar_plane_llm::meta::PLANE_DECLARATION,
    #[cfg(feature = "plane-mcp")]
    &busbar_plane_mcp::meta::PLANE_DECLARATION,
    #[cfg(feature = "plane-a2a")]
    &busbar_plane_a2a::meta::PLANE_DECLARATION,
    #[cfg(feature = "plane-voice")]
    &busbar_plane_voice::meta::PLANE_DECLARATION,
];
