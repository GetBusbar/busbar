// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WP1-GAP-plane-sections r3 section 2.2/2.7 and A-C2: a top-level key is a core section, or the
//! section of an admitted plane instance (carried raw under its instance name), or refused.

use super::*;
use crate::config::grammar::{Item, ItemKind, Standing};
use crate::config::resolve;
use std::collections::HashMap;

const BASE: &str = "providers: {}\nmodels: {}\npools: {}\n";

fn grammar(instances: &[&str]) -> Grammar {
    Grammar::new(Default::default(), Default::default(), Vec::new()).with_items(
        instances
            .iter()
            .map(|name| Item {
                kind: ItemKind::Section,
                name: (*name).to_owned(),
                module: format!("plane-{name}"),
                image: "linked".to_owned(),
                standing: Standing::Counts,
            })
            .collect(),
    )
}

fn read(text: &str, instances: &[&str]) -> Result<DeployCfg, busbar_contract::yaml::Error> {
    deploy_from_yaml_str(text, &grammar(instances))
}

fn yaml(text: &str) -> busbar_contract::yaml::Value {
    busbar_contract::yaml::from_str(text).unwrap()
}

#[test]
fn a_plane_section_under_its_instance_name_reaches_its_bag() {
    let deploy = read(&format!("mcp:\n  greeting: hi\n{BASE}"), &["mcp", "a2a"])
        .expect("a section named by an admitted instance parses");
    assert_eq!(
        deploy.door_sections().get("mcp"),
        Some(&yaml("greeting: hi"))
    );
    assert!(!deploy.door_sections().contains_key("a2a"));
}

#[test]
fn a_plane_sections_rate_card_and_fees_are_core_pricing_and_never_reach_the_bag() {
    let deploy = read(
        &format!(
            "mcp:\n  greeting: hi\n  rate_card:\n    srv_read: {{ units: {{ tool_calls: 3 }} }}\n  \
             fees: {{ per_request: 3 }}\n{BASE}"
        ),
        &["mcp"],
    )
    .expect("a plane section with core pricing parses");
    assert!(deploy.plane_rate_cards.contains_key("mcp"));
    assert!(deploy.plane_fees.contains_key("mcp"));
    assert_eq!(
        deploy.door_sections().get("mcp"),
        Some(&yaml("greeting: hi"))
    );
}

#[test]
fn a_dev_shape_section_is_refused_naming_the_plane_sections() {
    for word in ["tools", "agents", "streams", "webhooks", "interactions"] {
        let error = read(&format!("{word}:\n  x: 1\n{BASE}"), &["mcp", "a2a"])
            .expect_err("a retired dev shape is refused")
            .to_string();
        assert!(
            error.contains(&format!("unknown field `{word}`")),
            "{error}"
        );
        assert!(
            error.contains("no admitted plane answers to it")
                && error.contains("mcp")
                && error.contains("a2a"),
            "{error}"
        );
    }
}

#[test]
fn an_unknown_top_level_key_is_refused() {
    let error = read(&format!("no_such_key: 1\n{BASE}"), &[])
        .expect_err("rule 3")
        .to_string();
    assert!(error.contains("unknown field `no_such_key`"), "{error}");
    assert!(error.contains("no admitted plane answers to it"), "{error}");
}

#[test]
fn oauth_as_stays_a_core_section_beside_plane_sections() {
    let deploy = read(
        &format!("oauth_as:\n  issuer: https://as.example\nmcp:\n  a: 1\n{BASE}"),
        &["mcp"],
    )
    .expect("oauth_as is rule 1");
    assert!(deploy.oauth_as.is_some());
    assert!(!deploy.door_sections().contains_key("oauth_as"));
}

#[test]
fn a_section_hook_reference_is_judged_against_the_top_level_hooks() {
    let deploy = read(&format!("mcp:\n  hooks: [missing]\n{BASE}"), &["mcp"]).expect("parses");
    let errors = resolve(&deploy, &HashMap::new()).expect_err("an undefined hook is refused");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("mcp.hooks") && e.contains("`missing`")),
        "{errors:?}"
    );
}

#[test]
fn the_instance_name_parses_where_its_old_dev_key_is_refused() {
    // The Section items are the admitted planes' instance names (images::with_http_instances),
    // so a plane that declared `tools:` in 1.6.0-dev now answers to `mcp:` alone.
    read(&format!("mcp:\n  a: 1\n{BASE}"), &["mcp"]).expect("the instance name parses");
    let error = read(&format!("tools:\n  a: 1\n{BASE}"), &["mcp"])
        .expect_err("the old dev key is refused")
        .to_string();
    assert!(error.contains("plane sections are: mcp"), "{error}");
}
