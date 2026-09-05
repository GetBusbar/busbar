// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reads-not-restates guarantee for the LLM `PLANE_DECL` — see the doc comment on the\n//! `plane_decl_identity_tests` declaration in `lib.rs`. Relocated out of `lib.rs` per the\n//! tests-in-their-own-file convention.

#[test]
fn the_llm_plane_reads_the_registry_it_does_not_restate_it() {
    let field: fn() -> &'static [&'static str] = super::PLANE_DECL.wire_format_names;
    let reader: fn() -> &'static [&'static str] = busbar_substrate::proto::known_protocols;
    assert_eq!(
        field as usize, reader as usize,
        "PLANE_DECL.wire_format_names must BE busbar_substrate::proto::known_protocols (the registry \
             read), not a restated dialect list"
    );
}
