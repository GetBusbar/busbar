// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHIPPED `anthropic` ENTRY DECLARES NATIVE STRUCTURED OUTPUTS FOR EVERY MODEL ANTHROPIC LISTS.
//! A JSON output mode on an Anthropic lane without `native_structured_output` is refused with 400,
//! so a documented model missing from the catalog would refuse requests Anthropic serves. The list
//! is Anthropic's structured-outputs supported models
//! (platform.claude.com/docs/en/build-with-claude/structured-outputs), resolved here by the LLM
//! plane's rule: the first `model_capabilities` rule whose `*` glob matches the wire model wins.

use busbar_contract::json::{JsonContainerTrait as _, JsonValueTrait as _};

/// A `*` glob, the only wildcard `model_capabilities` takes (the LLM plane's `glob_match`).
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

fn native_structured_output(model: &str) -> bool {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../providers.yaml");
    let text = std::fs::read_to_string(&path).expect("the shipped catalog is readable");
    let catalog: busbar_contract::json::Value =
        busbar_contract::yaml::from_str(&text).expect("the catalog is YAML");
    let entry = &catalog["anthropic"];
    let rule = entry["model_capabilities"]
        .as_array()
        .expect("the anthropic entry lists model capabilities")
        .iter()
        .find(|r| {
            r["models"]
                .as_array()
                .is_some_and(|g| g.iter().any(|g| glob(g.as_str().unwrap_or(""), model)))
        });
    rule.and_then(|r| r["native_structured_output"].as_bool())
        .or_else(|| entry["native_structured_output"].as_bool())
        .unwrap_or(false)
}

#[test]
fn every_model_anthropic_lists_for_structured_outputs_is_native_in_the_shipped_catalog() {
    for model in [
        "claude-fable-5-2",
        "claude-fable-5-1",
        "claude-fable-5",
        "claude-mythos-5-2",
        "claude-mythos-5-1",
        "claude-mythos-5",
        "claude-mythos-preview",
        "claude-opus-5-5",
        "claude-opus-5",
        "claude-sonnet-5-5",
        "claude-sonnet-5",
        "claude-haiku-5-5",
        "claude-haiku-4-5",
        "claude-opus-4-8",
        "claude-opus-4-7",
        "claude-opus-4-6",
        "claude-opus-4-5",
        "claude-sonnet-4-6",
        "claude-sonnet-4-5",
        "claude-sonnet-4-5-20250929",
    ] {
        assert!(native_structured_output(model), "{model}");
    }
    for model in [
        "claude-opus-4-1",
        "claude-opus-4-1-20250805",
        "claude-3-7-sonnet-latest",
    ] {
        assert!(
            !native_structured_output(model),
            "{model} is not on Anthropic's list"
        );
    }
}
