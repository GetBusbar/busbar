// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lane-capability cases the retired engine crate's tests pinned, ported onto the plane's own
//! shaping tables: the first matching model rule over the provider's own keys, and the shipped
//! provider catalog's declared capabilities as the plane resolves them per wire model. Each test
//! cites the legacy test it ports.

use busbar_contract::ir::egress_prep::{LaneCaps, MaxOutputKey};
use busbar_plane_llm::exchange::shaping::Shaping;
use serde_json::{json, Map, Value};

/// The lane capabilities the plane resolves for `wire` on a provider whose settings are `provider`.
fn caps_for(provider: &Value, wire: &str) -> LaneCaps {
    let s = Shaping::from_settings(&json!({
        "providers": { "p": provider },
        "models": { "m": { "provider": "p", "upstream_model": wire } }
    }))
    .expect("reads");
    s.lane("m").expect("the lane").caps
}

/// A provider declaring nothing resolves every capability to its default; a provider-level key
/// applies to every model; the FIRST model rule whose glob matches the wire model overrides it.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/lane_caps_config_tests.rs::lane_caps_default_to_the_pre_capability_forms_and_resolve_provider_then_model_rule`
/// (its deployment-over-catalog arm is the root's merge:
/// `serve_door_exchange_ported::a_deployments_capability_key_overrides_the_catalogs`).
#[test]
fn a_first_matching_model_rule_overrides_the_providers_own_key() {
    let bare = json!({"protocol": "openai"});
    assert_eq!(caps_for(&bare, "gpt-4o"), LaneCaps::NONE);
    assert_eq!(LaneCaps::NONE, LaneCaps::default());
    let ruled = json!({
        "protocol": "openai",
        "max_output_key": "max_completion_tokens",
        "model_capabilities": [
            { "models": ["claude-opus-5*", "*-sonnet-5*"], "max_output_key": "max_tokens",
              "anthropic_adaptive_thinking": true, "native_structured_output": true },
            { "models": ["*"], "anthropic_adaptive_thinking": false, "reasoning_none": true }
        ]
    });
    assert_eq!(
        caps_for(&ruled, "gpt-5").max_output_key,
        MaxOutputKey::MaxCompletionTokens
    );
    let newest = caps_for(&ruled, "claude-sonnet-5-20260101");
    assert!(newest.anthropic_adaptive_thinking && newest.native_structured_output);
    assert_eq!(newest.max_output_key, MaxOutputKey::MaxTokens);
    assert!(
        !newest.reasoning_none,
        "only the FIRST matching rule applies"
    );
    let older = caps_for(&ruled, "claude-sonnet-4-5");
    assert!(!older.anthropic_adaptive_thinking && !older.native_structured_output);
    assert!(older.reasoning_none, "the catch-all rule matched it");
}

/// The shipped catalog's entries for `names`, as the plane is handed a provider's fields.
fn catalog(names: &[&str]) -> Map<String, Value> {
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../providers.yaml"),
    )
    .expect("read providers.yaml");
    let all: Value = serde_yaml::from_str(&raw).expect("parse providers.yaml");
    names
        .iter()
        .map(|n| {
            let entry = all
                .get(*n)
                .unwrap_or_else(|| panic!("the catalog names {n}"));
            ((*n).to_string(), entry.clone())
        })
        .collect()
}

/// The catalog provider `name`'s capabilities for `wire`.
fn shipped(entries: &Map<String, Value>, name: &str, wire: &str) -> LaneCaps {
    caps_for(&entries[name], wire)
}

/// The shipped catalog: `openai` writes its cap as `max_completion_tokens`, every compatible host
/// keeps the defaults, and the first-party `anthropic` entry's newest models take adaptive thinking
/// and native structured outputs while its older models keep the defaults.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/lane_caps_config_tests.rs::shipped_catalog_declares_the_lane_capabilities`.
#[test]
fn the_shipped_catalog_declares_the_lane_capabilities() {
    let hosts = ["groq", "together", "oci-genai", "deepseek", "openrouter"];
    let mut names = vec!["openai", "anthropic"];
    names.extend(hosts);
    let c = catalog(&names);
    assert_eq!(
        shipped(&c, "openai", "gpt-5").max_output_key,
        MaxOutputKey::MaxCompletionTokens
    );
    for host in hosts {
        assert_eq!(shipped(&c, host, "any-model"), LaneCaps::NONE, "{host}");
    }
    for newest in [
        "claude-opus-4-7",
        "claude-opus-5",
        "claude-sonnet-5-20260101",
        "claude-fable-5-1",
    ] {
        let caps = shipped(&c, "anthropic", newest);
        assert!(
            caps.anthropic_adaptive_thinking && caps.native_structured_output,
            "{newest}: {caps:?}"
        );
    }
    for older in [
        "claude-opus-4-5",
        "claude-sonnet-4-5",
        "claude-haiku-4-5",
        "claude-3-7-sonnet",
    ] {
        assert_eq!(shipped(&c, "anthropic", older), LaneCaps::NONE, "{older}");
    }
}

/// The shipped catalog: Claude models that cannot switch thinking off are `thinking_always_on` on
/// the first-party and bedrock entries (keeping adaptive thinking and native structured output);
/// the GPT-5.1 and 5.2 ids are `reasoning_none` on `openai` and `responses`; every other id keeps
/// both defaults; `openai`'s own output-cap key still applies under the rule; a compatible host
/// declares neither.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/lane_caps_config_tests.rs::shipped_catalog_declares_reasoning_none_and_thinking_always_on`.
#[test]
fn the_shipped_catalog_declares_reasoning_none_and_thinking_always_on() {
    let c = catalog(&["anthropic", "bedrock", "openai", "responses", "groq"]);
    for (name, model) in [
        ("anthropic", "claude-opus-5-5"),
        ("anthropic", "claude-opus-5-5-20260901"),
        ("anthropic", "claude-fable-5"),
        ("anthropic", "claude-fable-5-1"),
        ("bedrock", "anthropic.claude-opus-5-5-v1:0"),
        ("bedrock", "us.anthropic.claude-fable-5-1-v1:0"),
        ("bedrock", "global.anthropic.claude-fable-5-v1:0"),
    ] {
        let caps = shipped(&c, name, model);
        assert!(
            caps.thinking_always_on
                && caps.anthropic_adaptive_thinking
                && caps.native_structured_output
                && !caps.reasoning_none,
            "{model}: {caps:?}"
        );
    }
    for (name, model) in [
        ("anthropic", "claude-opus-5"),
        ("anthropic", "claude-opus-4-7"),
        ("anthropic", "claude-sonnet-5"),
        ("anthropic", "claude-sonnet-4-5"),
        ("bedrock", "us.anthropic.claude-opus-5-v1:0"),
        ("bedrock", "anthropic.claude-sonnet-4-5-20250929-v1:0"),
        ("bedrock", "amazon.nova-pro-v1:0"),
    ] {
        assert!(!shipped(&c, name, model).thinking_always_on, "{model}");
    }
    for name in ["openai", "responses"] {
        for model in [
            "gpt-5.1",
            "gpt-5.1-2025-11-13",
            "gpt-5.2",
            "gpt-5.2-2025-12-11",
        ] {
            let caps = shipped(&c, name, model);
            assert!(
                caps.reasoning_none && !caps.thinking_always_on,
                "{name} {model}: {caps:?}"
            );
        }
        for model in ["gpt-5", "gpt-5-mini", "gpt-5.1-mini", "gpt-4o", "o3"] {
            assert!(!shipped(&c, name, model).reasoning_none, "{name} {model}");
        }
    }
    assert_eq!(
        shipped(&c, "openai", "gpt-5.1").max_output_key,
        MaxOutputKey::MaxCompletionTokens
    );
    assert_eq!(shipped(&c, "groq", "gpt-5.1"), LaneCaps::NONE);
}
