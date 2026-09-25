//! The LANE-CAPABILITY resolution a provider entry declares, tested where the plane owns it
//! (architect ruling LANECAPS-MOVE). Moved from the kernel's config tests with the logic: the
//! provider entry is merged by THIS plane's `resolve_provider` (the kernel's
//! `merge_provider_fallback` is its byte-identical copy for a build without this plane), and
//! `lane_caps_for` below hands its four keys to the plane's resolver EXACTLY as `appbuild` does when
//! it builds a lane.

use std::collections::HashMap;

use busbar_substrate_values::ir::egress_prep::{LaneCaps, MaxOutputKey};
use busbar_substrate_values::ir::lane_caps::{
    resolve_lane_caps, MaxOutputKeyCfg, ModelCapabilities, ProviderLaneCaps,
};

use crate::engine::build_runtime::{
    resolve_provider as merge_provider_fallback, ProviderCfg, ProviderDef, ProviderDeploy,
};

/// The resolved entry's lane capabilities for one wire model, wired field by field as `appbuild`
/// wires them into `LaneInput::lane_caps`.
trait LaneCapsFor {
    fn lane_caps_for(&self, wire_model: &str) -> LaneCaps;
}

impl LaneCapsFor for ProviderCfg {
    fn lane_caps_for(&self, wire_model: &str) -> LaneCaps {
        resolve_lane_caps(
            ProviderLaneCaps {
                max_output_key: self.max_output_key,
                anthropic_adaptive_thinking: self.anthropic_adaptive_thinking,
                native_structured_output: self.native_structured_output,
            },
            &self.model_capabilities,
            wire_model,
        )
    }
}

/// A minimal ProviderDef for resolve() tests.
fn provider_def(protocol: &str, base_url: &str) -> ProviderDef {
    ProviderDef {
        protocol: protocol.to_string(),
        base_url: base_url.to_string(),
        error_map: HashMap::new(),
        health: None,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
        max_output_key: None,
        anthropic_adaptive_thinking: None,
        native_structured_output: None,
        model_capabilities: Vec::new(),
    }
}

/// A minimal ProviderDeploy whose credential is `{ env: <var> }`, parsed from the YAML an operator
/// writes (every other key omitted).
fn provider_deploy(env_var: &str) -> ProviderDeploy {
    serde_yaml::from_str(&format!("api_key: {{ env: {env_var} }}")).expect("minimal deployment")
}

// ── lane capabilities (architect ruling on OAI-01, ANT-07/09/10) ────────────────────────────────

#[test]
fn lane_caps_default_to_the_pre_capability_forms_and_resolve_provider_then_model_rule() {
    let mut def = provider_def("openai", "https://api.example.com");
    let deploy = provider_deploy("K");
    // Nothing declared: every default.
    let cfg = merge_provider_fallback(&def, &deploy);
    assert_eq!(cfg.lane_caps_for("gpt-4o"), LaneCaps::NONE);
    // A provider-level key applies to every model; the first matching model rule overrides it.
    def.max_output_key = Some(MaxOutputKeyCfg::MaxCompletionTokens);
    def.model_capabilities = vec![ModelCapabilities {
        models: vec!["claude-opus-5*".to_string(), "*-sonnet-5*".to_string()],
        max_output_key: Some(MaxOutputKeyCfg::MaxTokens),
        anthropic_adaptive_thinking: Some(true),
        native_structured_output: Some(true),
        ..Default::default()
    }];
    let cfg = merge_provider_fallback(&def, &deploy);
    assert_eq!(
        cfg.lane_caps_for("gpt-5").max_output_key,
        MaxOutputKey::MaxCompletionTokens
    );
    let newest = cfg.lane_caps_for("claude-sonnet-5-20260101");
    assert!(newest.anthropic_adaptive_thinking && newest.native_structured_output);
    assert_eq!(newest.max_output_key, MaxOutputKey::MaxTokens);
    let older = cfg.lane_caps_for("claude-sonnet-4-5");
    assert!(!older.anthropic_adaptive_thinking && !older.native_structured_output);
    // A deployment value overrides the catalog's.
    let mut deploy2 = provider_deploy("K");
    deploy2.max_output_key = Some(MaxOutputKeyCfg::MaxTokens);
    let cfg = merge_provider_fallback(&def, &deploy2);
    assert_eq!(
        cfg.lane_caps_for("gpt-5").max_output_key,
        MaxOutputKey::MaxTokens
    );
}

/// OAI-01 / ANT-07/09/10 at the CATALOG: the shipped providers.yaml resolves the `openai` provider
/// to `max_completion_tokens` and every OpenAI-compatible host to the default `max_tokens`, and the
/// `anthropic` provider's newest models to adaptive thinking + native structured outputs while its
/// older models keep the defaults.
#[test]
fn shipped_catalog_declares_the_lane_capabilities() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml"))
        .expect("read providers.yaml");
    let defs: HashMap<String, ProviderDef> =
        serde_yaml::from_str(&raw).expect("parse providers.yaml");
    let resolved = |name: &str| merge_provider_fallback(&defs[name], &provider_deploy("K"));
    assert_eq!(
        resolved("openai").lane_caps_for("gpt-5").max_output_key,
        MaxOutputKey::MaxCompletionTokens
    );
    for host in ["groq", "together", "oci-genai", "deepseek", "openrouter"] {
        assert_eq!(
            resolved(host).lane_caps_for("any-model"),
            LaneCaps::NONE,
            "{host} must keep the defaults"
        );
    }
    let anthropic = resolved("anthropic");
    for newest in [
        "claude-opus-4-7",
        "claude-opus-5",
        "claude-sonnet-5-20260101",
        "claude-fable-5-1",
    ] {
        let caps = anthropic.lane_caps_for(newest);
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
        assert_eq!(anthropic.lane_caps_for(older), LaneCaps::NONE, "{older}");
    }
}

/// At the CATALOG: the shipped providers.yaml declares `thinking_always_on` for the
/// Claude models that cannot switch thinking off (Opus 5.5, Fable 5.x) on the first-party
/// `anthropic` entry and on `bedrock`, keeping adaptive thinking + native structured output; and
/// `reasoning_none` for the GPT-5.1 / 5.2 ids on `openai` and `responses`. Every id outside those
/// patterns resolves both to the default `false` (today's bytes).
#[test]
fn shipped_catalog_declares_reasoning_none_and_thinking_always_on() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml"))
        .expect("read providers.yaml");
    let defs: HashMap<String, ProviderDef> =
        serde_yaml::from_str(&raw).expect("parse providers.yaml");
    let resolved = |name: &str| merge_provider_fallback(&defs[name], &provider_deploy("K"));
    let (anthropic, bedrock) = (resolved("anthropic"), resolved("bedrock"));
    for (lane, model) in [
        (&anthropic, "claude-opus-5-5"),
        (&anthropic, "claude-opus-5-5-20260901"),
        (&anthropic, "claude-fable-5"),
        (&anthropic, "claude-fable-5-1"),
        (&bedrock, "anthropic.claude-opus-5-5-v1:0"),
        (&bedrock, "us.anthropic.claude-fable-5-1-v1:0"),
        (&bedrock, "global.anthropic.claude-fable-5-v1:0"),
    ] {
        let caps = lane.lane_caps_for(model);
        assert!(
            caps.thinking_always_on
                && caps.anthropic_adaptive_thinking
                && caps.native_structured_output
                && !caps.reasoning_none,
            "{model}: {caps:?}"
        );
    }
    for (lane, model) in [
        (&anthropic, "claude-opus-5"),
        (&anthropic, "claude-opus-4-7"),
        (&anthropic, "claude-sonnet-5"),
        (&anthropic, "claude-sonnet-4-5"),
        (&bedrock, "us.anthropic.claude-opus-5-v1:0"),
        (&bedrock, "anthropic.claude-sonnet-4-5-20250929-v1:0"),
        (&bedrock, "amazon.nova-pro-v1:0"),
    ] {
        assert!(!lane.lane_caps_for(model).thinking_always_on, "{model}");
    }
    for name in ["openai", "responses"] {
        let lane = resolved(name);
        for model in [
            "gpt-5.1",
            "gpt-5.1-2025-11-13",
            "gpt-5.2",
            "gpt-5.2-2025-12-11",
        ] {
            let caps = lane.lane_caps_for(model);
            assert!(
                caps.reasoning_none && !caps.thinking_always_on,
                "{name} {model}: {caps:?}"
            );
        }
        for model in ["gpt-5", "gpt-5-mini", "gpt-5.1-mini", "gpt-4o", "o3"] {
            assert!(
                !lane.lane_caps_for(model).reasoning_none,
                "{name} {model} must keep the default"
            );
        }
    }
    // The `openai` entry's provider-level max_output_key still applies to the reasoning_none rule.
    assert_eq!(
        resolved("openai").lane_caps_for("gpt-5.1").max_output_key,
        MaxOutputKey::MaxCompletionTokens
    );
    // An OpenAI-compatible host declares neither.
    assert_eq!(resolved("groq").lane_caps_for("gpt-5.1"), LaneCaps::NONE);
}
