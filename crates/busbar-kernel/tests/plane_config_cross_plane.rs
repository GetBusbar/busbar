// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PARSE-TIME PLANE-BOUNDARY RULE, proven on the REAL plane crates.
//!
//! Relocated here from `src/plane/tests/config_tests.rs` (the A6/HostCtx dev-dependency-cycle
//! cleanup): it registers the real `busbar_llm`/`busbar_mcp`/`busbar_a2a` planes and drives their
//! REAL config validators (`busbar_a2a::a2a::config::validate_agent`, `busbar_mcp::mcp::config::
//! validate_server`) against core's own `config_sections()`/`refuse_cross_plane_reference` grammar —
//! which only type-checks (`register_test_plane(&LLM_PLANE)` takes core's OWN
//! `PlaneDecl`) with ONE `busbar_kernel` in the graph. See `plane_integration.rs`'s header for the
//! full rationale. The other tests in `config_tests.rs`/`sections_tests.rs` name no real plane crate
//! and stay there.
//!
//! `the_resolve_time_refusal_fires_on_a_bare_name_that_binds_across_the_boundary` (from
//! `src/plane/tests/config_tests.rs`) and `the_refusal_message_is_actionable` (from
//! `src/plane/tests/sections_tests.rs`) joined this file in the "fix the 38" pass: both assert that
//! [`RefError`]'s rendered Display PROSE contains a real plane's own config-section name
//! (`"tools"`/`"agents"`), which `cargo xtask gate construction`'s `neutral-no-dialect` rule (ceiling
//! 0) forbids a `#[cfg(test)]` fixture inside `busbar-kernel` itself from asserting — core may name
//! no plane, real or synthetic-under-a-real-key. An integration target that already depends on the
//! real plane crates is exactly where that prose is licensed to be pinned.

use busbar_kernel::plane::config::{config_sections, refuse_cross_plane_reference};
use busbar_kernel::plane::{PlaneSections, RefError};

/// Register the real `[llm, mcp, a2a]` roster in the process registry — idempotent (first-wins), so
/// every test can call it unconditionally regardless of run order.
fn register_planes() {
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
    busbar_kernel::plane::registry::register_test_plane(&LLM_PLANE);
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

/// The rendered message says which plane, which name, and where it actually lives. This is the text
/// an operator sees at boot, so it is pinned rather than left to drift.
///
/// Relocated from `src/plane/tests/sections_tests.rs`: it pins the same real section-name PROSE
/// (`"tools"`, `"agents"`) as the test above — see this file's header.
#[test]
fn the_refusal_message_is_actionable() {
    register_planes();
    let mut s: PlaneSections<&'static str> = PlaneSections::default();
    s.insert("llm", "fast", "a pool");
    s.insert("mcp", "filesystem", "an mcp server");
    s.insert("a2a", "planner", "an agent");

    let msg = s.resolve("mcp", "planner").unwrap_err().to_string();
    assert!(msg.contains("planner"), "names the entry: {msg}");
    assert!(
        msg.contains("tools"),
        "names the referencing section: {msg}"
    );
    assert!(msg.contains("agents"), "names the defining section: {msg}");

    let unknown = s.resolve("mcp", "nowhere").unwrap_err().to_string();
    assert!(unknown.contains("nowhere"));
    assert!(unknown.contains("tools"));
    assert!(
        !unknown.contains("agents"),
        "an unknown name must not invent a plane it lives on: {unknown}"
    );
}

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

/// The llm plane's registry row, assembled kernel-side from its contract declaration
/// and its behaviour table.
static LLM_PLANE: busbar_kernel::plane::registry::PlaneDecl =
    busbar_kernel::plane::registry::PlaneDecl::assemble(
        busbar_llm::PLANE_DECLARATION,
        busbar_llm::PLANE_HOOKS,
    );
