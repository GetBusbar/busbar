// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PARSE-TIME PLANE-BOUNDARY RULE, and the proof that it is one.
//!
//! This module checks two properties:
//!
//!
//!   1. Is the section list DERIVED, and is there exactly one of it? A list written twice agrees
//!      only by accident, and the accident ends the day somebody adds a section.
//!   2. Does a plane busbar does not have cost anything? The rule takes its sections as a
//!      PARAMETER, so the answer is a section name and nothing else — no config module, no
//!      validator, no refusal type.

use busbar_kernel::config::plane_sections::{
    config_sections, judge_hook_ref, refuse_cross_plane_reference, validate_section_hooks,
    HookRefError,
};

#[test]
fn the_section_list_is_derived_from_the_config_grammar_rather_than_written() {
    crate::dist_root_install::install();
    let mut expected: Vec<&'static str> = Vec::new();
    for s in busbar_kernel::plane_driver::dispatch::plane_keys()
        .map(|k| busbar_kernel::plane_driver::dispatch::plane_decl(k).config_section)
        .chain(busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS)
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

#[test]
fn a_third_plane_costs_a_section_name_and_nothing_else() {
    crate::dist_root_install::install();
    let mut sections = config_sections();
    assert!(
        !sections.contains(&"bays"),
        "`bays` must be a plane busbar genuinely does not have, or this proves nothing"
    );
    sections.push("bays");

    let err = refuse_cross_plane_reference("`bays.dock`", "bays.sanitizer", &sections)
        .expect_err("a plane busbar does not have is still a plane a hook may not reach onto");
    assert_eq!(
        err,
        "`bays.dock`: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
         `bays.sanitizer` reaches onto the `bays:` plane, and no entry on one plane may reference \
         an entry on another. Did you mean the hook `sanitizer`?"
    );

    validate_section_hooks("`bays.hooks`", &["bays.sanitizer".to_string()], &sections)
        .expect_err("the section-level attach list is judged by the same rule");

    validate_section_hooks("`bays.hooks`", &["sanitizer".to_string()], &sections)
        .expect("a bare name is what a hook reference is, on every plane");

    assert_eq!(
        judge_hook_ref("bays.sanitizer", &config_sections()),
        Err(HookRefError::NotBare {
            hook: "bays.sanitizer".to_string()
        })
    );
}

#[test]
fn the_parse_time_refusal_fires_on_a_name_nothing_defines() {
    crate::dist_root_install::install();
    let sections = config_sections();
    let err = refuse_cross_plane_reference("`tools.search`", "agents.planner", &sections)
        .expect_err("a dotted name that reaches onto a plane is refused at parse time");
    assert!(
        err.contains("reaches onto the `agents:` plane"),
        "got: {err}"
    );
}

#[test]
fn every_refusal_arm_has_a_sentence_of_its_own() {
    crate::dist_root_install::install();
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

    assert_eq!(
        judge_hook_ref("  agents.planner  ", &sections),
        Err(HookRefError::CrossPlane {
            hook: "agents.planner".to_string(),
            section: "agents",
            rest: "planner".to_string(),
        })
    );
}
