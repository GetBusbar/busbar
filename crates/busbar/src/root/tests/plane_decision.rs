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

// `PLANE_DECL` is a `const`, so `PLANE_DECL.fallback` is known at compile time and an `assert!` on
// it in a `#[test]` is dead weight (clippy: assertion has a constant value) — a `const _` check
// keeps the exact same guarantee (this plane never sets the LLM plane's fallback flag) enforced at
// compile time instead, which is strictly earlier than a test run would catch it.
const _: () = assert!(
    !PLANE_DECL.fallback,
    "the fallback catch-all is the LLM plane's flag and exactly one plane sets it"
);

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

// ── THE SECTION'S GRAMMAR, NOT JUST ITS NAME ────────────────────────────────────────────────────
// The four tests above prove the declaration's IDENTITY. These four prove the thing identity alone
// bought nothing for: that what an operator writes under `decisions:` is read through the plane's
// OWN typed shape. Before the seam hooks were wired the section fell through
// `deserialize_plane_section`'s `None` arm to an untyped `RawPlaneSection` capture, so
// `decisions: "hello"` PARSED and the typed section's `deny_unknown_fields` never ran — a config an
// operator writes that does nothing. Each test below fails on that build and passes on this one.
//
// They run under a `TestRegistryIsolation` seeded with exactly this decl: the seam resolves the
// owning plane out of the PROCESS registry, so the registry is the input under test and it is
// installed explicitly rather than depended on from a sibling test's registration.

/// The parse seam is resolved through the plane REGISTRY, so a test that means to exercise it has to
/// install the decl. Seeded (not `empty()` + `register_test_plane`) because the serial lock is not
/// reentrant — see `TestRegistryIsolation::seeded`.
fn decisions_registered() -> busbar_kernel::plane::registry::TestRegistryIsolation {
    busbar_kernel::plane::registry::TestRegistryIsolation::seeded(&[&PLANE_DECL])
}

/// A document whose only interesting key is `decisions:`. The three other top-level keys are the
/// minimum `DeployCfg` shape the sibling config tests already use.
fn doc(decisions: &str) -> String {
    format!("providers: {{}}\nmodels: {{}}\npools: {{}}\n{decisions}")
}

/// THE FINDING, AS A TEST. `decisions: "hello"` is not a section — it is a scalar where a mapping
/// belongs. With the seam unwired it was captured raw and ACCEPTED, which is the exact shape of a
/// support ticket: the operator's block is syntactically impossible and boot says nothing.
#[test]
fn a_scalar_decisions_block_is_refused() {
    let _reg = decisions_registered();
    let err = busbar_kernel::config::deploy_from_yaml_str(&doc("decisions: \"hello\"\n"))
        .expect_err("`decisions: \"hello\"` is not a section and must be refused, not captured");
    let msg = err.to_string();
    assert!(
        msg.contains(CONFIG_SECTION),
        "the refusal must name the key the operator wrote, got: {msg}"
    );
}

/// `deny_unknown_fields` INSIDE the block, which is the whole reason the plane's own typed section
/// carries it: a typo'd member must fail boot rather than be silently ignored. The raw capture
/// accepted `modles:` without a word.
#[test]
fn a_typo_d_member_of_the_decisions_block_is_refused() {
    let _reg = decisions_registered();
    let err = busbar_kernel::config::deploy_from_yaml_str(&doc("decisions:\n  modles: {}\n"))
        .expect_err("a typo'd member of `decisions:` must fail boot (deny_unknown_fields)");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("modles"),
        "the refusal must name the unknown member, got: {msg}"
    );
}

/// THE ASSERTION THE LANDING COMMIT'S TEST COULD NOT MAKE. `is_present()` is true of a raw capture
/// too, so it cannot tell typed from untyped. This reads the parsed value back as the PLANE'S OWN
/// `DecisionsSection` — which only the wired `parse_section` hook can produce.
#[test]
fn a_valid_decisions_block_lands_as_the_plane_s_own_typed_section() {
    let _reg = decisions_registered();
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&doc(
        "decisions:\n  models:\n    jev: { provider: typesafe, upstream_model: jev-1.13.0 }\n",
    ))
    .expect("a valid `decisions:` block must parse");

    let section = deploy
        .decisions
        .0
        .as_any()
        .downcast_ref::<super::DecisionsCfg>()
        .expect(
            "`decisions:` must land as the plane's own typed section, not as an untyped raw capture",
        );
    let model = section
        .0
        .models
        .get("jev")
        .expect("the operator's model entry must survive the lowering");
    assert_eq!(model.provider, "typesafe");
    assert_eq!(model.upstream_model.as_deref(), Some("jev-1.13.0"));
    assert!(deploy.decisions.0.is_present());
}

/// THE `default_section` HALF. Without it an ABSENT `decisions:` falls back to the neutral raw
/// default, so the carrier's type would depend on whether the operator wrote the block — and the
/// downcast above would hold for a configured deployment and fail for an unconfigured one.
#[test]
fn an_absent_decisions_block_defaults_to_the_plane_s_own_empty_section() {
    let _reg = decisions_registered();
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&doc(""))
        .expect("a document with no `decisions:` section still parses");
    let section = deploy
        .decisions
        .0
        .as_any()
        .downcast_ref::<super::DecisionsCfg>()
        .expect("an ABSENT `decisions:` must default to the plane's own empty section");
    assert!(section.0.models.is_empty());
    assert!(
        !deploy.decisions.0.is_present(),
        "an empty section is not a section the operator wrote"
    );
}

/// **THE DECISION PLANE COUNTS NO FEE UNIT** (ARCHITECT ruling, fees): it admits nobody (see
/// `the_declaration_mounts_nothing_and_admits_nobody`), so no request or session of it is ever
/// counted and any `decisions.fees` figure would charge nothing — boot and `--validate` refuse each
/// such key, naming it and the (empty) counted list. A fee of 0 charges what it says and passes.
#[test]
fn a_decisions_fee_refuses_because_the_plane_counts_no_fee_unit() {
    let _reg = decisions_registered();
    let verdict = |fees: &str| {
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&doc(&format!(
            "decisions:\n  fees: {fees}\n"
        )))
        .expect("the config parses");
        let root = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        busbar_kernel::config_validate::validate(&root)
    };
    let refusal = |unit: &str| {
        Err(vec![format!(
            "decisions.fees.{unit} is not counted by this plane (counted: none); remove it"
        )])
    };
    assert_eq!(verdict("{ per_request: 2 }"), refusal("per_request"));
    assert_eq!(verdict("{ per_session: 40 }"), refusal("per_session"));
    assert_eq!(verdict("{ per_request: 0 }"), Ok(()));
}
