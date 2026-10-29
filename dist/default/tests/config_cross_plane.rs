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
// the `resolve_provider` hook since the retired engine crate's deletion, so the
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
    use busbar_kernel::config::plane_sections::PlaneCfg;
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
    // The section is judged by the door that declares it: the binary's `tools:` door.
    let door = linked::owning("tools").door;
    let section =
        busbar_kernel::plane_driver::door::DoorSection::new(door, "tools", effective("foo_bar"));
    let refused = section
        .validate_registry()
        .expect_err("an effective registry whose published names collide is refused");
    assert!(refused.contains("published as `foo_bar`"), "{refused}");
    busbar_kernel::plane_driver::door::DoorSection::new(door, "tools", effective("other_name"))
        .validate_registry()
        .expect("distinct published names pass");
}

/// A member naming nothing is an operator believing a request has somewhere to go when it does not.
/// 1.6.0: a plane's pool lives under its own verb (`tools.pools:`), so the dangling `search-us` is
/// named against `tools:`.
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

/// THE SECTION A POOL IS WRITTEN IN IS ITS PLANE: an `agents:` registration named in a `tools.pools`
/// pool is refused, and the message names the section the member actually lives in.
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
            .any(|e| e.contains("`planner`") && e.contains("`agents:`") && e.contains("straddle")),
        "the message says the member lives in another plane's section: {errs:?}"
    );
}

/// A plane's pool written in the top-level `pools:` is the model plane's pool there, so its members
/// are refused as unknown models, as 1.5.5 refused any pool member that named no model.
#[test]
fn a_plane_pool_in_the_top_level_pools_is_refused() {
    register_planes();
    let deploy = deploy_yaml(
        r#"
tools:
  search-eu: { url: "https://eu.example/t", pin: { mechanism: unpinned } }
  search-us: { url: "https://us.example/t", pin: { mechanism: unpinned } }
pools:
  search:
    members: [search-eu, search-us]
"#,
    );
    let refused = match resolve(&deploy, &HashMap::new()) {
        Err(errs) => errs,
        Ok(cfg) => busbar_kernel::config_validate::validate(&cfg).expect_err("refused"),
    };
    assert!(
        refused.iter().any(|e| e.contains("search-eu")),
        "the top-level pool's tool member is refused: {refused:?}"
    );
}

/// A pool named after a registration of its own plane would alias that registration's breaker cell
/// (the two share the keyspace), so it is refused.
#[test]
fn a_pool_named_like_a_registration_of_its_plane_is_refused() {
    register_planes();
    let deploy = deploy_yaml(
        r#"
tools:
  search: { url: "https://s.example/t", pin: { mechanism: unpinned } }
  search-eu: { url: "https://eu.example/t", pin: { mechanism: unpinned } }
  search-us: { url: "https://us.example/t", pin: { mechanism: unpinned } }
  pools:
    search:
      members: [search-eu, search-us]
"#,
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("an aliasing pool must refuse boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("`search` is also the id of a `tools:` registration")),
        "{errs:?}"
    );
}

/// A MALFORMED `pools:` UNDER ANY PLANE'S SECTION REFUSES BOOT, as 1.5.5 refused a malformed pool:
/// the reserved sub-key is read for every declared section alike (R1#5, Law 1), and the refusal
/// names where it was written.
#[test]
fn a_malformed_pools_block_under_any_plane_section_is_refused() {
    register_planes();
    for section in ["tools", "agents"] {
        for pools in [
            "[a, b]",
            "{ p: { members: not-a-list } }",
            "{ p: { members: [a, b], unknown_knob: 1 } }",
        ] {
            let deploy = deploy_yaml(&format!("{section}:\n  pools: {pools}\n"));
            let errs = resolve(&deploy, &HashMap::new())
                .expect_err("a malformed pools block must refuse boot");
            assert!(
                errs.iter()
                    .any(|e| e.starts_with(&format!("{section}.pools: "))),
                "`{section}.pools: {pools}` is refused naming where it was written: {errs:?}"
            );
        }
    }
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

/// A POOL'S `breaker:` BLOCK IS EVERY PLANE'S (BUSBAR-1.6.0.md THE DESIGN §1: "Any plugin gets all
/// functionality ... A capability one plane has and a sibling plane lacks is a gap to close"). The
/// top-level `pools:` have always carried a `breaker:` block held to Rule 6; a pool written under
/// another plane's section (`<verb>.pools`) takes the same key, so it is held to the same rule in
/// the same words, and the block it states goes with it to its plane's egress.
///
/// RED before the fix: the plane's pool carrier had no `breaker` key, so the block was never read,
/// never held to Rule 6 and never applied.
#[test]
fn a_planes_pool_breaker_block_is_held_to_the_same_rule_and_carried() {
    let pool = |base: u64| {
        let deploy = deploy_yaml(&format!(
            r#"
tools:
  search-eu: {{ url: "https://eu.example/t", pin: {{ mechanism: unpinned }} }}
  search-us: {{ url: "https://us.example/t", pin: {{ mechanism: unpinned }} }}
  pools:
    search:
      members: [search-eu, search-us]
      breaker: {{ base_cooldown_secs: {base}, max_cooldown_secs: 300 }}
"#
        ));
        resolve(&deploy, &HashMap::new()).expect("the pool resolves")
    };
    let refused = busbar_kernel::config_validate::validate(&pool(0)).expect_err("refused");
    assert!(
        refused.iter().any(|e| e
            == "pool 'search' breaker base_cooldown_secs must be >= 1 (got 0); a zero cooldown \
                re-admits a tripped backend immediately, defeating the breaker's back-off"),
        "the top-level pools' Rule 6, in its own words: {refused:?}"
    );
    let carried = pool(30);
    let block = carried.plane_pools["tools"]["search"]
        .breaker
        .as_ref()
        .expect("the block goes with the pool to its plane");
    assert_eq!(
        (block.base_cooldown_secs, block.max_cooldown_secs),
        (30, 300)
    );
    if let Err(errors) = busbar_kernel::config_validate::validate(&carried) {
        assert!(
            !errors.iter().any(|e| e.contains("breaker")),
            "a sound block is not refused: {errors:?}"
        );
    }
}
