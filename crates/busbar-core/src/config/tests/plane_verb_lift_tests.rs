// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CONFIG-MODEL STAGE 1 — THE REGISTRY-DRIVEN PLANE-VERB LIFT.
//!
//! Three questions, mirroring `plane/tests/config_tests.rs`'s own three-question shape for the
//! sibling (hook-reference) grammar derivation:
//!
//!   1. Is the TOP-LEVEL plane-verb lift set a FUNCTION of the plane registry (registered planes
//!      minus the sections core still owns concretely), rather than the hardcoded literal it used
//!      to be? `crates/busbar-core` carries `busbar-llm`/`busbar-mcp`/`busbar-a2a` as its own
//!      built-in test planes (`busbar-voice` is not a dev-dependency of this crate, so `streams`
//!      is not independently reachable here — the derivation is proven the same way regardless of
//!      which planes happen to be registered).
//!   2. Does a plane dropped in from OUTSIDE core — with no concrete `DeployCfg` field of its own —
//!      still PARSE, landing in the generic overflow carrier, instead of being refused by
//!      `deny_unknown_fields`?
//!   3. Is the frozen "expected one of" refusal for a GENUINELY unknown top-level key still
//!      byte-identical, and does it name neither a real plane-verb section nor the dropped-in one?

use crate::config::deploy_from_yaml_str;
use crate::plane::config::PlaneCfg;
use crate::plane::registry::PlaneDecl;

/// A PLANE BUSBAR DOES NOT HAVE — the same shape `plane/tests/registry_tests.rs`'s `WIDGET_PLANE`
/// uses, but registered through the NEUTRAL test seam
/// ([`busbar_substrate::plane::registry::register_test_plane`]) rather than folded locally, so it
/// reaches the config PRE-PASS's own registry read (`crate::plane::registry::plane_decls()`), not
/// just `config_sections_from`'s explicit decl list. A distinct key/section from `registry_tests`'s
/// own `WIDGET_PLANE` (which never touches the process registry) so the two cannot collide.
static GIZMO_PLANE: PlaneDecl = PlaneDecl {
    key: "gizmo_stage1_test",
    fallback: false,
    config_section: "gizmos",
    scope_kinds: &["gizmo"],
    subject_noun: "fronted gizmo",
    admin_noun: "fronted-gizmo",
    audit_kind: "gizmo_thing",
    wire_format_names: || &["gizmorpc"],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    card_signing_domain: None,
    card_kid_prefix: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    #[cfg(feature = "openapi-schema")]
    openapi_schemas: None,
    on_swap: None,
    // `None`: no `parse_section` hook, so the pre-pass's generic
    // `crate::plane::config::deserialize_plane_section` falls back to `RawPlaneSection`, capturing
    // whatever the operator wrote without naming a plane type — exactly the path a dropped-in
    // plane with no config grammar of its own takes.
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    owned_config_sections: &[],
    resolve_provider: None,
};

/// Register [`GIZMO_PLANE`] into the process test registry, CONFINED to the returned guard's
/// lifetime. Unlike a bare `register_test_plane` call (which — with no unregister — would leak
/// `GIZMO_PLANE` into every sibling test sharing this `#[lib] test` binary, including the two
/// enumeration tests over `crate::plane::plane_keys()` in `plane/tests/{plane_tests,sections_tests}.rs`
/// that assert the exact built-in plane set), this takes
/// [`busbar_substrate::plane::registry::TestRegistryIsolation::snapshot`] FIRST — which holds the
/// process test-registry serial lock for the guard's lifetime (so no sibling's read or registration
/// races or interleaves) — and registers afterwards, so `Drop` rolls the registration back to the
/// pre-call snapshot the instant the caller's `#[test]` returns. The caller MUST hold the returned
/// guard for its whole test body (`let _iso = register_gizmo_plane();`): dropping it early re-opens
/// the same leak this exists to close.
#[must_use = "GIZMO_PLANE stays registered — and the shared registry stays confined — only while this guard is alive"]
fn register_gizmo_plane() -> busbar_substrate::plane::registry::TestRegistryIsolation {
    let iso = busbar_substrate::plane::registry::TestRegistryIsolation::snapshot();
    busbar_substrate::plane::registry::register_test_plane(&GIZMO_PLANE);
    iso
}

/// A minimal YAML document valid without any plane-verb section, so each test below can add
/// exactly the top-level key it is proving something about.
fn base_yaml() -> String {
    "providers: {}\npools:\n  models: {}\n".to_string()
}

// ══ 1. THE LIFT SET IS REGISTRY-DERIVED, NOT HARDCODED ═══════════════════════════════════════════

/// The plane-verb half of the lift set is exactly [`crate::plane::registry::plane_decls`]'s own
/// `config_section`s minus [`crate::plane::registry::CORE_OWNED_CONCRETE_SECTIONS`] — recomputed
/// independently here (rather than asserted against a hand-typed literal) so the test proves the
/// FUNCTION, not today's specific plane roster.
#[test]
fn plane_verb_lift_set_is_derived_from_the_registry_and_excludes_core_owned_sections() {
    let derived = crate::config::prepass::plane_verb_lift_keys();

    let mut expected: Vec<&'static str> = Vec::new();
    for decl in crate::plane::registry::plane_decls() {
        let section = decl.config_section;
        if !crate::plane::registry::CORE_OWNED_CONCRETE_SECTIONS.contains(&section)
            && !expected.contains(&section)
        {
            expected.push(section);
        }
    }
    assert_eq!(
        derived, expected,
        "the plane-verb lift set must be exactly the registry's own derivation, not a literal"
    );

    // `pools` is the LLM plane's own `config_section` and is core-owned concretely — it must never
    // be lifted, exactly as the design requires.
    assert!(
        !derived.contains(&"pools"),
        "the core-owned `pools:` section must be excluded from the plane-verb lift: {derived:?}"
    );
    for core_owned in crate::plane::registry::CORE_OWNED_CONCRETE_SECTIONS {
        assert!(
            !derived.contains(core_owned),
            "no core-owned-concrete section may appear in the plane-verb lift: {derived:?}"
        );
    }

    // Non-vacuous: `busbar-mcp`/`busbar-a2a` are this crate's own built-in test planes, so `tools`
    // and `agents` are always present regardless of which OTHER planes a sibling test registered.
    assert!(
        derived.contains(&"tools"),
        "the MCP plane's own section must be in the derived lift: {derived:?}"
    );
    assert!(
        derived.contains(&"agents"),
        "the A2A plane's own section must be in the derived lift: {derived:?}"
    );
}

// ══ 2. A DROPPED-IN PLANE'S SECTION PARSES INTO THE OVERFLOW CARRIER ═════════════════════════════

/// A registered plane with NO concrete `DeployCfg` field of its own — `gizmos:` names no field on
/// that frozen struct — still PARSES: the registry-derived lift pulls it off the document before
/// `deny_unknown_fields` ever sees it, and [`crate::config::mod::DeployCfg::extra_plane_sections`]
/// is what it lands in.
///
/// Watched RED before this stage: with the old hardcoded `LIFTED_TOP_LEVEL_KEYS` literal, a
/// registered-but-not-named plane's section was simply not in the lift list, so `gizmos:` would
/// have failed the SAME `providers: {}\nmodels: {}\ngizmos: {}` document with `deny_unknown_fields`
/// naming `gizmos` — the exact failure this stage exists to remove.
#[test]
fn a_dropped_in_plane_section_parses_into_the_overflow_carrier() {
    let _iso = register_gizmo_plane();

    let yaml = format!("{}gizmos:\n  widget: yes\n", base_yaml());
    let deploy = deploy_from_yaml_str(&yaml).expect(
        "a registered plane's section with no concrete DeployCfg field must still parse, into the \
         overflow carrier",
    );

    assert!(
        deploy.extra_plane_sections.contains_key("gizmos"),
        "the `gizmos:` section must land in the generic overflow carrier"
    );
    assert!(
        deploy.extra_plane_sections["gizmos"].is_present(),
        "the operator-written content must be visible through the carried `PlaneCfg`"
    );

    // An ABSENT `gizmos:` block parses too (a registered plane's section is optional, exactly as
    // `tools:`/`agents:`/`streams:` are) and leaves the overflow carrier without that key.
    let deploy_absent = deploy_from_yaml_str(&base_yaml())
        .expect("a registered plane's section is optional, absent must still parse");
    assert!(
        !deploy_absent.extra_plane_sections.contains_key("gizmos"),
        "an absent section must not appear in the overflow carrier"
    );
}

// ══ 3. THE FROZEN REFUSAL FOR A GENUINELY UNKNOWN KEY IS UNCHANGED ═══════════════════════════════

/// A top-level key that names NO section — not a plane-verb one, not the dropped-in plane's own —
/// is refused exactly as 1.5.5 refused it: `deny_unknown_fields`'s own "expected one of" list,
/// which never names a `#[serde(skip)]` carrier (that was true of `tools`/`agents`/`streams` before
/// this stage and stays true of `extra_plane_sections` after it), so the refusal mentions none of
/// the plane-verb sections, the dropped-in plane's section, nor the overflow carrier's own field
/// name.
#[test]
fn an_unknown_top_level_key_refusal_names_no_lifted_or_carrier_key() {
    let _iso = register_gizmo_plane();

    let yaml = format!("{}sprockets: {{}}\n", base_yaml());
    let err = deploy_from_yaml_str(&yaml)
        .expect_err("a top-level key naming no section must still be refused");
    let msg = err.to_string();

    assert!(
        msg.contains("unknown field") && msg.contains("sprockets"),
        "must be the deny_unknown_fields refusal naming the actual unknown key: {msg}"
    );
    for must_not_appear in [
        "tools",
        "agents",
        "streams",
        "gizmos",
        "extra_plane_sections",
    ] {
        assert!(
            !msg.contains(must_not_appear),
            "the frozen refusal must not name `{must_not_appear}`: {msg}"
        );
    }
}
