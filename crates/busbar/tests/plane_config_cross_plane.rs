// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PARSE-TIME PLANE-BOUNDARY RULE, proven on the REAL planes this binary links.
//!
//! Relocated here from `src/plane/tests/config_tests.rs` / `sections_tests.rs`: the planes come from
//! the test-linked table (`tests/linked/mod.rs`) and are addressed by the config section each
//! declares, so this file names no plane crate, key or type. Each plane's REAL validator is reached
//! CONFIG-DRIVEN — the section is parsed and resolved through the kernel's own config entry points,
//! exactly as boot does — against core's own `config_sections()`/`refuse_cross_plane_reference`
//! grammar. The rendered prose pinned below names config sections (`tools`, `agents`), which is
//! what an operator reads at boot.

mod linked;

use busbar_kernel::plane::config::{config_sections, refuse_cross_plane_reference};
use busbar_kernel::plane::{PlaneSections, RefError};

/// Register every test-linked plane in the process registry — idempotent (first-wins), so every
/// test can call it unconditionally regardless of run order.
fn register_planes() {
    linked::install();
}

/// The refusal a named-definition section's own validator gives for entry `x` carrying one hook
/// reference `hook`, reached CONFIG-DRIVEN: the section is parsed through the kernel's lift
/// (`deploy_from_yaml_str`, where the declaring plane parses its own section) and then resolved, and
/// the one message naming the hook is returned — from whichever of the two stages refused.
fn refusal_for(section: &str, hook: &str) -> String {
    let yaml = format!(
        "providers: {{}}\nmodels: {{}}\n{section}:\n  x:\n    url: \"https://vendor.example/x\"\n    pin: {{ mechanism: unpinned }}\n    hooks: [\"{hook}\"]\n"
    );
    let errors: Vec<String> = match busbar_kernel::config::deploy_from_yaml_str(&yaml) {
        Err(e) => vec![e.to_string()],
        Ok(deploy) => busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
            .err()
            .unwrap_or_default(),
    };
    errors
        .into_iter()
        .find(|e| e.contains(hook))
        .unwrap_or_else(|| panic!("the `{section}:` plane must refuse `{hook}`"))
}

/// EVERY section the grammar declares is refused BY BOTH PLANES' production validators, and the two
/// refusals differ in nothing but the caller's own label for the site.
///
/// This is the whole point of the unit expressed as a test: it iterates the DERIVATION, so a plane
/// or a section added to either table is covered here the moment it is added, with no edit to this
/// test and none to either protocol's config module.
#[test]
fn every_section_the_grammar_declares_is_refused_on_both_planes() {
    // Both planes' validators judge a hook reference against the PROCESS section registry, read through
    // the neutral `plane_sections` provider seam — so every plane must be registered for them to
    // recognise every OTHER plane's declared section as a cross-plane reach. Idempotent by key, so
    // this is a no-op past the first run.
    register_planes();

    let agents = linked::owning("agents").config_section;
    let tools = linked::owning("tools").config_section;
    for section in config_sections() {
        let hook = format!("{section}.some-hook");

        let on_agents = refusal_for(agents, &hook);
        let on_tools = refusal_for(tools, &hook);

        let agents_body = on_agents
            .split_once(&format!("`{agents}.x`"))
            .map(|(_, body)| body)
            .expect("the `agents:` plane keeps its own wording for WHERE");
        let tools_body = on_tools
            .split_once(&format!("`{tools}.x`"))
            .map(|(_, body)| body)
            .expect("the `tools:` plane keeps its own wording for WHERE");
        assert_eq!(
            agents_body, tools_body,
            "one rule, one sentence: the planes may differ only in the site they name"
        );
        assert!(
            agents_body.contains(&format!("reaches onto the `{section}:` plane")),
            "the refusal must NAME the section reached onto, got: {on_agents}"
        );
    }
}

/// THE RESOLVE-TIME REFUSAL, on a name that EXISTS on a sibling plane — the resolve-time twin of the
/// parse-time rule above. The input is a BARE name — no dot, nothing for the parse-time rule to
/// object to. It passes that rule cleanly and is refused only because the BINDING crosses the
/// boundary. Neither check subsumes the other, which is why merging them would delete one.
///
/// Relocated from `src/plane/tests/config_tests.rs`: the final assertion pins the rendered message's
/// PROSE, which names the real A2A plane's own config section (`"agents"`) — see this file's header.
#[test]
fn the_resolve_time_refusal_fires_on_a_bare_name_that_binds_across_the_boundary() {
    register_planes();
    let agents = linked::owning("agents").key;
    let tools = linked::owning("tools").key;
    let mut sections: PlaneSections<u8> = PlaneSections::default();
    sections.insert(agents, "planner", 1);

    // The parse-time rule has NO objection to this name.
    refuse_cross_plane_reference("`tools.search`", "planner", &config_sections())
        .expect("a bare name is legal in shape; the boundary it crosses is a binding, not a shape");

    let err = sections
        .resolve(tools, "planner")
        .expect_err("a name defined on a sibling plane is a boundary violation");
    assert_eq!(
        err,
        RefError::CrossPlane {
            name: "planner".to_string(),
            referenced_from: tools,
            defined_in: agents,
        }
    );
    assert!(
        err.to_string().contains("which is defined in `agents`"),
        "the refusal DIAGNOSES rather than merely denying, got: {err}"
    );
}

/// The rendered message says which plane, which name, and where it actually lives. This is the text
/// an operator sees at boot, so it is pinned rather than left to drift.
///
/// Relocated from `src/plane/tests/sections_tests.rs`: it pins the same real section-name PROSE
/// (`"tools"`, `"agents"`) as the test above — see this file's header.
#[test]
fn the_refusal_message_is_actionable() {
    register_planes();
    let models = linked::fallback().key;
    let tools = linked::owning("tools").key;
    let agents = linked::owning("agents").key;
    let mut s: PlaneSections<&'static str> = PlaneSections::default();
    s.insert(models, "fast", "a pool");
    s.insert(tools, "filesystem", "a tool server");
    s.insert(agents, "planner", "an agent");

    let msg = s.resolve(tools, "planner").unwrap_err().to_string();
    assert!(msg.contains("planner"), "names the entry: {msg}");
    assert!(
        msg.contains("tools"),
        "names the referencing section: {msg}"
    );
    assert!(msg.contains("agents"), "names the defining section: {msg}");

    let unknown = s.resolve(tools, "nowhere").unwrap_err().to_string();
    assert!(unknown.contains("nowhere"));
    assert!(unknown.contains("tools"));
    assert!(
        !unknown.contains("agents"),
        "an unknown name must not invent a plane it lives on: {unknown}"
    );
}
