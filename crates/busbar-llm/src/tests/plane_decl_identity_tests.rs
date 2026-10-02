// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reads-not-restates guarantee for the LLM `PLANE_HOOKS` — see the doc comment on the
//! `plane_decl_identity_tests` declaration in `lib.rs`. Relocated out of `lib.rs` per the
//! tests-in-their-own-file convention.

#[test]
fn the_llm_plane_reads_the_registry_it_does_not_restate_it() {
    let field: fn() -> &'static [&'static str] = super::PLANE_HOOKS.wire_format_names;
    let reader: fn() -> &'static [&'static str] = busbar_kernel::proto::known_protocols;
    assert_eq!(
        field as usize, reader as usize,
        "PLANE_HOOKS.wire_format_names must BE busbar_kernel::proto::known_protocols (the registry \
             read), not a restated dialect list"
    );
}

/// THE PLANE'S OPERATOR-VISIBLE IDENTITY, pinned as LITERALS by the plane that declares it: the key
/// every metric, log and record carries, and that it is the ONE fallback catch-all. Moved here from
/// busbar-kernel's `registry_cross_plane.rs` (K3; architect ruling N02), where the kernel now asserts
/// its `fallback_key()` answers whichever linked plane declares the flag.
#[test]
fn the_plane_declares_its_published_key_and_is_the_fallback() {
    let d = &super::PLANE_DECLARATION;
    assert_eq!(d.key, "llm");
    assert!(
        d.fallback,
        "the fallback catch-all every unclaimed path falls through to"
    );
    assert_eq!(d.config_section, "pools");
    assert_eq!(d.audit_kind, "pool");
}
