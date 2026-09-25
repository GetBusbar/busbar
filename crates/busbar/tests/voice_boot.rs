// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! M5 — THE VOICE PLANE BOOTS. These assertions run under `cargo test -p busbar --features
//! plane-voice`: the composition root links `busbar-voice`, the plane OWNS the `streams:` section,
//! and its section reaches the config grammar. Compiled out (the default build) this file is empty,
//! so the deletion gate that builds `busbar` WITHOUT voice still passes.
#![cfg(feature = "plane-voice")]

use busbar_kernel::plane::registry::{
    check_owned_config_claims, register_test_plane, CORE_OWNED_CONCRETE_SECTIONS,
};

// `CORE_OWNED_CONCRETE_SECTIONS` is the kernel's REAL list — the one the boot guard judges against —
// imported rather than mirrored. A copy used to sit here on the grounds that the const was
// `pub(crate)`; it is `pub`, and a mirror is a second list that can drift from the first while every
// test below goes on passing against the wrong one (item 267).

/// The voice plane DECLARES `streams:` as its owned section and wires the two seam hooks that let
/// `DeployCfg` deserialize/validate it without naming a `busbar_voice` type.
#[test]
fn voice_decl_owns_streams_and_wires_the_section_hooks() {
    let d = &busbar_voice::PLANE_DECLARATION;
    let hooks = &busbar_voice::PLANE_HOOKS;
    assert_eq!(d.config_section, "streams");
    assert_eq!(d.owned_config_sections, &["streams"]);
    assert!(
        hooks.parse_section.is_some(),
        "voice must PARSE its owned `streams:` section (parse_section wired)"
    );
    assert!(
        hooks.default_section.is_some(),
        "an ABSENT `streams:` must default to StreamsCfg::default() (default_section wired)"
    );
}

/// The dup-claim guard ADMITS the real voice decl: `streams` is not core-owned and voice is its sole
/// claimant. (The collision-refusal half is proven directly in `busbar_kernel`'s registry unit test,
/// which owns a second synthetic claimant against the real `CORE_OWNED_CONCRETE_SECTIONS`.)
#[test]
fn dup_claim_guard_admits_the_real_voice_decl() {
    check_owned_config_claims(&[&busbar_voice::PLANE_DECLARATION], CORE_OWNED_CONCRETE_SECTIONS).expect(
        "`streams` ∉ core-owned and voice is the sole claimant — the real voice claim must be admitted",
    );
}

/// A synthetic SECOND plane that also claims `streams`, built by functional update off the REAL voice
/// decl (every field but `key` copied, so it claims `streams` exactly as voice does) — the planted
/// collision the dup-claim guard must refuse by construction.
static RIVAL_CLAIMS_STREAMS: busbar_contract::plane::PlaneDeclaration =
    busbar_contract::plane::PlaneDeclaration {
        key: "rival-voice",
        ..busbar_voice::PLANE_DECLARATION
    };

/// The dup-claim guard REFUSES a planted collision: two planes claiming `streams` is a hard error that
/// names the contested section and both claimants. This is the boot-validate leg's (c) assertion.
#[test]
fn dup_claim_guard_refuses_a_planted_streams_collision() {
    let err = check_owned_config_claims(
        &[&busbar_voice::PLANE_DECLARATION, &RIVAL_CLAIMS_STREAMS],
        CORE_OWNED_CONCRETE_SECTIONS,
    )
    .expect_err("two planes claiming `streams` MUST be refused — one plane's grammar would answer for the other's");
    assert!(
        err.contains("streams") && err.contains("voice") && err.contains("rival-voice"),
        "the refusal must name the contested section and both claimants, got: {err}"
    );
}

/// Registering the voice plane puts its owned `streams:` section into the config-grammar section list
/// `config_sections()` reports — the list the cross-plane hook-reference rule (and every reader that
/// asks "what top-level sections exist") judges against.
#[test]
fn registering_voice_puts_streams_into_config_sections() {
    static VOICE_PLANE: busbar_kernel::plane::registry::PlaneDecl =
        busbar_kernel::plane::registry::PlaneDecl::assemble(
            busbar_voice::PLANE_DECLARATION,
            busbar_voice::PLANE_HOOKS,
        );
    register_test_plane(&VOICE_PLANE);
    let sections = busbar_kernel::plane::config::config_sections();
    assert!(
        sections.contains(&"streams"),
        "voice's owned `streams:` section must reach the config grammar once the plane is \
         registered, got: {sections:?}"
    );
}

/// Every section core owns is REFUSED to a plane that claims it — asked of the kernel's own list, so
/// a section added to (or evicted from) it is judged here the day it moves, with no copy to update.
/// Voice's `streams` is the admitted control: the refusal is about the section, not the plane.
#[test]
fn a_plane_claiming_any_real_core_owned_section_is_refused() {
    assert!(
        !CORE_OWNED_CONCRETE_SECTIONS.is_empty(),
        "non-vacuity: core owns concrete sections, and this test must be asked of them"
    );
    assert!(
        !CORE_OWNED_CONCRETE_SECTIONS.contains(&"streams"),
        "voice's `streams:` is not core-owned; the admitted control depends on it"
    );
    for section in CORE_OWNED_CONCRETE_SECTIONS {
        let owned: &'static [&'static str] = Box::leak(Box::new([*section]));
        let grabber = busbar_contract::plane::PlaneDeclaration {
            key: "section-grabber",
            owned_config_sections: owned,
            ..busbar_voice::PLANE_DECLARATION
        };
        let err = check_owned_config_claims(&[&grabber], CORE_OWNED_CONCRETE_SECTIONS)
            .expect_err("a plane claiming a core-owned section must be refused");
        assert!(
            err.contains(section),
            "the refusal must name the core-owned section `{section}`, got: {err}"
        );
    }
}
