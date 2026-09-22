// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PARSE-TIME PLANE-BOUNDARY RULE, proven on the REAL plane crates.
//!
//! Relocated here from `src/plane/tests/config_tests.rs` (the A6/HostCtx dev-dependency-cycle
//! cleanup): it registers the real `busbar_llm`/`busbar_mcp`/`busbar_a2a` planes and drives their
//! REAL config validators (`busbar_a2a::a2a::config::validate_agent`, `busbar_mcp::mcp::config::
//! validate_server`) against core's own `config_sections()`/`refuse_cross_plane_reference` grammar —
//! which only type-checks (`register_test_plane(&busbar_llm::PLANE_DECL)` takes core's OWN
//! `PlaneDecl`) with ONE `busbar_kernel` in the graph. See `plane_integration.rs`'s header for the
//! full rationale. The other four tests in `config_tests.rs` name no plane crate and stay there.

use busbar_kernel::plane::config::config_sections;

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
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
    busbar_kernel::plane::registry::register_test_plane(&busbar_llm::PLANE_DECL);

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
