// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `config::resolve` AGREEMENT TESTS, relocated here from `src/config/tests/tests.rs`:
//! each drives core's OWN `resolve` / `merge_provider_fallback` against the REAL planes this binary
//! links (the test-linked table, `tests/linked/mod.rs`), so the busbar_kernel instance on both sides
//! of the call is the one the planes link — which only an integration-test target gives. The
//! configuration is CONFIG-DRIVEN: a YAML document parsed through the kernel's own entry point, so
//! the sections are lifted by whichever registered plane declares them and this file names no plane
//! crate and no plane type.

mod linked;

use busbar_kernel::config::{deploy_from_yaml_str, resolve, DeployCfg};
use std::collections::HashMap;

/// Register every test-linked plane in the process registry, idempotent (first-wins) — needed
/// because the kernel lifts a `tools:`/`agents:` section only when a registered plane declares it.
fn register_planes() {
    linked::install();
}

/// A DeployCfg parsed from `sections` through the kernel's own config entry point
/// (`deploy_from_yaml_str`, the boot path's lift), after the linked planes are installed — so a
/// section is lifted exactly when a registered plane declares it, as in a shipped binary. Empty
/// `providers:`/`models:` stand in for the required keys this file's refusals do not concern.
fn deploy_yaml(sections: &str) -> DeployCfg {
    register_planes();
    let text = format!("providers: {{}}\nmodels: {{}}\n{sections}");
    deploy_from_yaml_str(&text).unwrap_or_else(|e| panic!("the test config parses: {e}\n{text}"))
}

// (`resolve_provider_hook_and_core_fallback_agree` is RETIRED with its subject: no plane implements
// the `resolve_provider` hook since the retired engine crate's deletion (DEV-GREEN row 83), so the
// served provider merge IS core's `merge_provider_fallback`, the one path; covered by
// busbar-kernel `ir/tests/lane_caps_tests.rs` (F25 rows 485-487) and `config/tests/tests.rs`.)

#[test]
fn resolve_refuses_a_publish_as_collision_so_validate_and_boot_agree() {
    register_planes();
    // The SUBTLE collision — an override against a namespaced default nobody typed — because it is
    // the one that survives a partial implementation of the rule.
    // The section is judged by its plane's own `validate` where it is read (a door plane's section
    // is judged as it is lifted), so the one read `--validate` and boot share refuses it — at the
    // lift or at `resolve`, whichever owns the rule; never not at all.
    let colliding = r#"
tools:
  foo:
    url: "https://foo/"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other/"
    pin: { mechanism: unpinned }
    tools_allow: { anything: { publish_as: foo_bar } }
"#;
    let refused = deploy_from_yaml_str(&format!("providers: {{}}\nmodels: {{}}\n{colliding}"))
        .map(|deploy| resolve(&deploy, &HashMap::new()).map(|_| ()))
        .map_or_else(|e| Some(e.to_string()), |r| r.err().map(|e| e.join("\n")))
        .expect("a config whose published names are not unique is refused");
    assert!(refused.contains("published as `foo_bar`"), "{refused}");

    // GREEN, same shape, one name changed: the refusal is about the collision and nothing else.
    let deploy = deploy_yaml(
        r#"
tools:
  foo:
    url: "https://foo/"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other/"
    pin: { mechanism: unpinned }
    tools_allow: { anything: { publish_as: other_name } }
"#,
    );
    resolve(&deploy, &HashMap::new()).expect("distinct published names must resolve");
}

/// THE EFFECTIVE REGISTRY IS JUDGED WHOLE AT `resolve`: a door section holding entries no parse ever
/// read together (the file's, plus what the management surface wrote) is held to its door's
/// section-wide rules there, so an applied registration whose published name collides with another's
/// is refused exactly as the same file would be. RED without `DoorSection::validate_registry` running
/// the door's `validate`; GREEN for the same section with distinct names.
#[test]
fn a_door_sections_effective_registry_is_judged_whole_at_resolve() {
    use busbar_kernel::plane::config::PlaneCfg;
    register_planes();
    let effective = |publish: &str| -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            r#"
foo:
  url: "https://foo/"
  pin: {{ mechanism: unpinned }}
  tools_allow: {{ bar: {{}} }}
other:
  url: "https://other/"
  pin: {{ mechanism: unpinned }}
  tools_allow: {{ anything: {{ publish_as: {publish} }} }}
"#
        ))
        .expect("yaml")
    };
    let section = busbar_kernel::plane::door::DoorSection::new("tools", effective("foo_bar"));
    let refused = section
        .validate_registry()
        .expect_err("an effective registry whose published names collide is refused");
    assert!(refused.contains("published as `foo_bar`"), "{refused}");
    busbar_kernel::plane::door::DoorSection::new("tools", effective("other_name"))
        .validate_registry()
        .expect("distinct published names pass");
}

/// A member naming nothing is an operator believing a request has somewhere to go when it does not.
/// 1.6.0: the pool lives in the ONE neutral `pools:` map; kind is INFERRED from the resolvable
/// member (`search-eu` → a `tools:` server), so the dangling `search-us` is named against `tools:`.
#[test]
fn a_tool_pool_member_that_names_no_server_is_refused() {
    register_planes();
    let deploy = deploy_yaml(
        r#"
tools:
  search-eu: { url: "https://eu.example/t", pin: { mechanism: unpinned } }
pools:
  search:
    members: [search-eu, search-us]
"#,
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("a dangling member must refuse boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("search-us") && e.contains("`tools:`")),
        "the message names the missing entry and the section it belongs in: {errs:?}"
    );
}

/// KIND IS INFERRED, SO A POOL MUST BE HOMOGENEOUS: a pool whose members span two nouns cannot be
/// assigned a single plane and is refused with the homogeneity error.
#[test]
fn a_pool_may_not_straddle_two_planes() {
    register_planes();
    let deploy = deploy_yaml(
        r#"
agents:
  planner: { url: "https://a.example/card", pin: { mechanism: unpinned } }
tools:
  search-eu: { url: "https://eu.example/t", pin: { mechanism: unpinned } }
pools:
  mixed:
    members: [planner, search-eu]
"#,
    );
    let errs =
        resolve(&deploy, &HashMap::new()).expect_err("a cross-plane member must refuse boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("more than one plane") && e.contains("same kind")),
        "the message says the pool's members are not all one kind: {errs:?}"
    );
}

/// A one-member pool changes nothing, so writing one is a mistake and is named as one.
#[test]
fn a_failover_pool_needs_two_members() {
    register_planes();
    let deploy = deploy_yaml(
        r#"
agents:
  only-one: { url: "https://a.example/card", pin: { mechanism: unpinned } }
pools:
  planner:
    members: [only-one]
"#,
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("a one-member pool must refuse boot");
    assert!(
        errs.iter().any(|e| e.contains("at least TWO members")),
        "{errs:?}"
    );
}
