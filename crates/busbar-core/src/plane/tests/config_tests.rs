// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PARSE-TIME PLANE-BOUNDARY RULE, and the proof that it is one.
//!
//! Three questions are asked here, and each of them used to be unanswerable because the rule
//! existed twice:
//!
//!   1. Is the section list DERIVED, and is there exactly one of it? A list written twice agrees
//!      only by accident, and the accident ends the day somebody adds a section.
//!   2. Does a plane busbar does not have cost anything? The rule takes its sections as a
//!      PARAMETER, so the answer is a section name and nothing else — no config module, no
//!      validator, no refusal type.
//!   3. Are the two cross-plane refusals still TWO? [`crate::plane::config`] refuses a SHAPE at
//!      parse time; [`crate::plane::PlaneSections::resolve`] refuses a BINDING at resolve time.
//!      Merging them would delete a check rather than deduplicate one, so both are exercised on
//!      inputs the other cannot see.

use crate::config::named_map::NamedMapSection;
use crate::plane::config::{
    config_sections, judge_hook_ref, refuse_cross_plane_reference, validate_section_hooks,
    HookRefError,
};
use crate::plane::{PlaneSections, RefError};

// ══ 1. THE SECTION LIST EXISTS ONCE, AND IS DERIVED ══════════════════════════════════════════════

/// The list is a FUNCTION OF THE CONFIG GRAMMAR's two declaring tables, not a literal that happens
/// to match them today. Written as `assert_eq!` against a recomputed union rather than against a
/// hand-typed expectation: a hand-typed expectation is a third copy of the very literal this unit
/// deleted, and it would go green while the derivation rotted.
#[test]
fn the_section_list_is_derived_from_the_config_grammar_rather_than_written() {
    let mut expected: Vec<&'static str> = Vec::new();
    for s in crate::plane::plane_keys()
        .map(|k| crate::plane::plane_decl(k).config_section)
        .chain(NamedMapSection::ALL.iter().map(|s| s.key()))
    {
        if !expected.contains(&s) {
            expected.push(s);
        }
    }
    assert_eq!(
        config_sections(),
        expected,
        "the section list must be the union of the two tables that DECLARE the config grammar"
    );

    // A floor, so the equality above cannot hold vacuously if both sides collapse to nothing. The
    // five are the literal this unit deleted; they must still all be there.
    for was_hardcoded in ["pools", "tools", "agents", "export", "identity-providers"] {
        assert!(
            config_sections().contains(&was_hardcoded),
            "`{was_hardcoded}:` was in the deleted literal and must still be derived"
        );
    }
    assert!(
        config_sections().len() >= 5,
        "a truncated list would make every refusal test below pass vacuously"
    );
}

/// EVERY section the grammar declares is refused BY BOTH PLANES' production validators, and the two
/// refusals differ in nothing but the caller's own label for the site.
///
/// This is the whole point of the unit expressed as a test: it iterates the DERIVATION, so a plane
/// or a section added to either table is covered here the moment it is added, with no edit to this
/// test and none to either protocol's config module.
#[test]
fn every_section_the_grammar_declares_is_refused_on_both_planes() {
    for section in config_sections() {
        let hook = format!("{section}.some-hook");

        let a2a = busbar_a2a::a2a::config::validate_agent("x", &agent_with_hook(&hook))
            .expect_err(&format!("the `agents:` plane must refuse `{hook}`"));
        let mcp = busbar_mcp::mcp::config::validate_server("x", &server_with_hook(&hook))
            .expect_err(&format!("the `tools:` plane must refuse `{hook}`"));

        let a2a_body = a2a
            .strip_prefix("`agents.x`")
            .expect("the a2a plane keeps its own wording for WHERE");
        let mcp_body = mcp
            .strip_prefix("`tools.x`")
            .expect("the mcp plane keeps its own wording for WHERE");
        assert_eq!(
            a2a_body, mcp_body,
            "one rule, one sentence: the planes may differ only in the site they name"
        );
        assert!(
            a2a_body.contains(&format!("reaches onto the `{section}:` plane")),
            "the refusal must NAME the section reached onto, got: {a2a}"
        );
    }
}

// ══ 2. A THIRD PLANE COSTS A SECTION NAME AND NOTHING ELSE ═══════════════════════════════════════

/// THE ANALOGUE OF `a_fourth_stream_costs_a_record_type_and_nothing_else`: a plane busbar does not
/// have, validated and refused correctly, with NO config module, NO validator and NO refusal type
/// written for it.
///
/// `bays` is not a busbar plane and never has been. All it takes to be judged by the one rule is to
/// appear in the section list the rule is handed — which is exactly what a real fourth plane would
/// get for free by joining `Plane::ALL`.
#[test]
fn a_third_plane_costs_a_section_name_and_nothing_else() {
    let mut sections = config_sections();
    assert!(
        !sections.contains(&"bays"),
        "`bays` must be a plane busbar genuinely does not have, or this proves nothing"
    );
    sections.push("bays");

    // The parse-time rule refuses it, names it, and offers the bare name meant — with nothing
    // written anywhere for `bays`.
    let err = refuse_cross_plane_reference("`bays.dock`", "bays.sanitizer", &sections)
        .expect_err("a plane busbar does not have is still a plane a hook may not reach onto");
    assert_eq!(
        err,
        "`bays.dock`: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
         `bays.sanitizer` reaches onto the `bays:` plane, and no entry on one plane may reference \
         an entry on another. Did you mean the hook `sanitizer`?"
    );

    // The section-level list inherits it too, by the same call — a section attach is not a looser
    // rule, and a fourth plane does not get to be the exception.
    validate_section_hooks("`bays.hooks`", &["bays.sanitizer".to_string()], &sections)
        .expect_err("the section-level attach list is judged by the same rule");

    // And a BARE name on the new plane is still the legal form. A rule that refused everything
    // would pass the assertions above while being useless.
    validate_section_hooks("`bays.hooks`", &["sanitizer".to_string()], &sections)
        .expect("a bare name is what a hook reference is, on every plane");

    // The other direction of the same fact: without the new section in the list, `bays.sanitizer`
    // is merely NOT BARE — a different refusal with a different sentence. That is what makes the
    // list a real input rather than decoration.
    assert_eq!(
        judge_hook_ref("bays.sanitizer", &config_sections()),
        Err(HookRefError::NotBare {
            hook: "bays.sanitizer".to_string()
        })
    );
}

// ══ 3. TWO CROSS-PLANE REFUSALS, AND THEY ARE NOT THE SAME CHECK ═════════════════════════════════

/// THE PARSE-TIME REFUSAL, on a string, before anything is known to exist.
///
/// The input is deliberately one NOTHING DEFINES: no `planner` exists on any plane in this test, so
/// [`PlaneSections::resolve`] could not refuse this and would never see it. Only a SHAPE rule can.
#[test]
fn the_parse_time_refusal_fires_on_a_name_nothing_defines() {
    let sections = config_sections();
    let err = refuse_cross_plane_reference("`tools.search`", "agents.planner", &sections)
        .expect_err("a dotted name that reaches onto a plane is refused at parse time");
    assert!(
        err.contains("reaches onto the `agents:` plane"),
        "got: {err}"
    );

    // The proof that this check is not the resolve-time one: an EMPTY container — nothing defined
    // anywhere — cannot produce a `CrossPlane` for the same name. The resolve-time rule answers
    // `Unknown`, because there is nothing there to have crossed a boundary.
    let empty: PlaneSections<u8> = PlaneSections::default();
    assert_eq!(
        empty.resolve("mcp", "agents.planner"),
        Err(RefError::Unknown {
            name: "agents.planner".to_string(),
            plane: "mcp"
        }),
        "the resolve-time rule cannot see a shape violation; only the parse-time rule can"
    );
}

/// THE RESOLVE-TIME REFUSAL, on a name that EXISTS on a sibling plane.
///
/// The input is a BARE name — no dot, nothing for the parse-time rule to object to. It passes that
/// rule cleanly and is refused only because the BINDING crosses the boundary. Neither check
/// subsumes the other, which is why merging them would delete one.
#[test]
fn the_resolve_time_refusal_fires_on_a_bare_name_that_binds_across_the_boundary() {
    let mut sections: PlaneSections<u8> = PlaneSections::default();
    sections.insert("a2a", "planner", 1);

    // The parse-time rule has NO objection to this name.
    refuse_cross_plane_reference("`tools.search`", "planner", &config_sections())
        .expect("a bare name is legal in shape; the boundary it crosses is a binding, not a shape");

    let err = sections
        .resolve("mcp", "planner")
        .expect_err("a name defined on a sibling plane is a boundary violation");
    assert_eq!(
        err,
        RefError::CrossPlane {
            name: "planner".to_string(),
            referenced_from: "mcp",
            defined_in: "a2a",
        }
    );
    assert!(
        err.to_string().contains("which is defined in `agents`"),
        "the refusal DIAGNOSES rather than merely denying, got: {err}"
    );
}

// ══ THE REMAINING SENTENCES, so the total `From` has a reader for every arm ═══════════════════════

/// An empty name and a dotted name that names no section are DIFFERENT refusals with different
/// sentences. The `From` is total so that stays true when a fourth arm is added.
#[test]
fn every_refusal_arm_has_a_sentence_of_its_own() {
    let sections = config_sections();
    assert_eq!(
        refuse_cross_plane_reference("`tools.search`", "  ", &sections).unwrap_err(),
        "`tools.search`: `hooks:` contains an empty name"
    );
    assert_eq!(
        refuse_cross_plane_reference("`tools.search`", "a.b", &sections).unwrap_err(),
        "`tools.search`: `hooks:` may only name hooks from the top-level `hooks:` map, by bare \
         name. `a.b` is not a bare name."
    );
    // Whitespace around a reference does not launder it past the rule.
    assert_eq!(
        judge_hook_ref("  agents.planner  ", &sections),
        Err(HookRefError::CrossPlane {
            hook: "agents.planner".to_string(),
            section: "agents",
            rest: "planner".to_string(),
        })
    );
}

// ══ fixtures ═════════════════════════════════════════════════════════════════════════════════════

/// A minimal, otherwise-VALID `agents:` entry carrying one hook reference — so the only thing that
/// can fail the validator is the hook.
fn agent_with_hook(hook: &str) -> busbar_a2a::a2a::config::AgentDefCfg {
    serde_yaml::from_str::<busbar_a2a::a2a::config::AgentsCfg>(
        "x:\n  url: \"https://a2a.vendor/x\"\n  pin: { mechanism: unpinned }\n",
    )
    .expect("the fixture entry must parse")
    .agents
    .shift_remove("x")
    .map(|mut def| {
        def.hooks = vec![hook.to_string()];
        def
    })
    .expect("the fixture entry must be present")
}

/// The same, for the `tools:` plane.
fn server_with_hook(hook: &str) -> busbar_mcp::mcp::config::McpServerDefCfg {
    serde_yaml::from_str::<busbar_mcp::mcp::config::ToolsCfg>(
        "x:\n  url: \"https://mcp.internal/x\"\n  pin: { mechanism: unpinned }\n",
    )
    .expect("the fixture entry must parse")
    .servers
    .shift_remove("x")
    .map(|mut def| {
        def.hooks = vec![hook.to_string()];
        def
    })
    .expect("the fixture entry must be present")
}
