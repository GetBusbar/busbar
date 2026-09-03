// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! M5 — THE VOICE PLANE BOOTS. These assertions run under `cargo test -p busbar --features
//! plane-voice`: the composition root links `busbar-voice`, the plane OWNS the `streams:` section,
//! and its section reaches the config grammar. Compiled out (the default build) this file is empty,
//! so the deletion gate that builds `busbar` WITHOUT voice still passes.
#![cfg(feature = "plane-voice")]

use busbar_substrate::plane::registry::{check_owned_config_claims, register_test_plane};

/// The real `CORE_OWNED_CONCRETE_SECTIONS` (providers/models/pools/rate_card/limits) — mirrored here
/// because `busbar_core`'s const is `pub(crate)`. `busbar_core`'s own unit test
/// `dup_claim_guard_admits_streams_alone_and_refuses_a_streams_collision` proves the guard against the
/// REAL const; this literal is kept honest by that test plus the plane-config-noun gate.
const CORE_OWNED_CONCRETE_SECTIONS: &[&str] =
    &["providers", "models", "pools", "rate_card", "limits"];

/// The voice plane DECLARES `streams:` as its owned section and wires the two seam hooks that let
/// `DeployCfg` deserialize/validate it without naming a `busbar_voice` type.
#[test]
fn voice_decl_owns_streams_and_wires_the_section_hooks() {
    let d = &busbar_voice::PLANE_DECL;
    assert_eq!(d.config_section, "streams");
    assert_eq!(d.owned_config_sections, &["streams"]);
    assert!(
        d.parse_section.is_some(),
        "voice must PARSE its owned `streams:` section (parse_section wired)"
    );
    assert!(
        d.default_section.is_some(),
        "an ABSENT `streams:` must default to StreamsCfg::default() (default_section wired)"
    );
}

/// The dup-claim guard ADMITS the real voice decl: `streams` is not core-owned and voice is its sole
/// claimant. (The collision-refusal half is proven directly in `busbar_core`'s registry unit test,
/// which owns a second synthetic claimant against the real `CORE_OWNED_CONCRETE_SECTIONS`.)
#[test]
fn dup_claim_guard_admits_the_real_voice_decl() {
    check_owned_config_claims(&[&busbar_voice::PLANE_DECL], CORE_OWNED_CONCRETE_SECTIONS).expect(
        "`streams` ∉ core-owned and voice is the sole claimant — the real voice claim must be admitted",
    );
}

/// A synthetic SECOND plane that also claims `streams`, built by functional update off the REAL voice
/// decl (every field but `key` copied, so it claims `streams` exactly as voice does) — the planted
/// collision the dup-claim guard must refuse by construction.
static RIVAL_CLAIMS_STREAMS: busbar_substrate::plane::registry::PlaneDecl =
    busbar_substrate::plane::registry::PlaneDecl {
        key: "rival-voice",
        ..busbar_voice::PLANE_DECL
    };

/// The dup-claim guard REFUSES a planted collision: two planes claiming `streams` is a hard error that
/// names the contested section and both claimants. This is the boot-validate leg's (c) assertion.
#[test]
fn dup_claim_guard_refuses_a_planted_streams_collision() {
    let err = check_owned_config_claims(
        &[&busbar_voice::PLANE_DECL, &RIVAL_CLAIMS_STREAMS],
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
    register_test_plane(&busbar_voice::PLANE_DECL);
    let sections = busbar_core::plane::config::config_sections();
    assert!(
        sections.contains(&"streams"),
        "voice's owned `streams:` section must reach the config grammar once the plane is \
         registered, got: {sections:?}"
    );
}
