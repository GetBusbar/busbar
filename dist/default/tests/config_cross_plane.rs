// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use busbar_kernel::config::{deploy_from_yaml_str, resolve, DeployCfg};
use std::collections::HashMap;

fn register_planes() {
    linked::install();
}

fn deploy_yaml(sections: &str) -> DeployCfg {
    register_planes();
    let text = format!("providers: {{}}\nmodels: {{}}\n{sections}");
    deploy_from_yaml_str(&text).unwrap_or_else(|e| panic!("the test config parses: {e}\n{text}"))
}

#[test]
fn resolve_refuses_a_publish_as_collision_so_validate_and_boot_agree() {
    register_planes();

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
