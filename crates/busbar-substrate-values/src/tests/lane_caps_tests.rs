//! Tests for `ir/lane_caps.rs`. Moved VERBATIM from the kernel's config tests with the glob they
//! test (architect ruling LANECAPS-MOVE); only the item path changed.

// ── lane capabilities (architect ruling on OAI-01, ANT-07/09/10) ────────────────────────────────

#[test]
fn lane_caps_glob_matches_star_runs_only() {
    use crate::ir::lane_caps::glob_match;
    assert!(glob_match("claude-opus-4-7*", "claude-opus-4-7"));
    assert!(glob_match("claude-opus-4-7*", "claude-opus-4-7-20260301"));
    assert!(glob_match(
        "*sonnet-5*",
        "us.anthropic.claude-sonnet-5-v1:0"
    ));
    assert!(glob_match("gpt-5", "gpt-5"));
    assert!(!glob_match("gpt-5", "gpt-5-mini"));
    assert!(!glob_match("claude-opus-4-7*", "claude-opus-4-6"));
    assert!(!glob_match("a*b*c", "acb"));
}

/// A `model_capabilities` rule's `reasoning_none` / `thinking_always_on` reach the
/// resolved LaneCaps for a matching model only; a rule that omits them, and a model no rule matches,
/// keep the pre-capability defaults (today's bytes).
#[test]
fn rule_reasoning_none_and_thinking_always_on_resolve_per_model_and_default_off() {
    use crate::ir::egress_prep::LaneCaps;
    use crate::ir::lane_caps::{resolve_lane_caps, ModelCapabilities};
    let rules: Vec<ModelCapabilities> = serde_json::from_str(
        r#"[{"models": ["claude-fable-5*"], "thinking_always_on": true},
            {"models": ["gpt-5.1"], "reasoning_none": true},
            {"models": ["gpt-4o"]}]"#,
    )
    .expect("rules parse");
    let caps = |m: &str| resolve_lane_caps(Default::default(), &rules, m);
    assert!(caps("claude-fable-5-1").thinking_always_on);
    assert!(!caps("claude-fable-5-1").reasoning_none);
    assert!(caps("gpt-5.1").reasoning_none);
    assert!(!caps("gpt-5.1").thinking_always_on);
    assert_eq!(caps("gpt-4o"), LaneCaps::NONE);
    assert_eq!(caps("claude-sonnet-4-5"), LaneCaps::NONE);
}

/// The `bedrock` entry's `model_capabilities` from the shipped providers.yaml (written in flow /
/// JSON style so this crate can read it without a YAML parser). Moved here from the LLM plane's
/// suite (#83a SD-3): the catalog's resolution is the host's; the plane pins what its writer does
/// with the capabilities.
fn shipped_bedrock_rules() -> Vec<crate::ir::lane_caps::ModelCapabilities> {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml"))
        .expect("read providers.yaml");
    let entry = &raw[raw.find("\nbedrock:\n").expect("bedrock entry")..];
    let rules = &entry[entry
        .find("  model_capabilities:")
        .expect("bedrock model_capabilities")..];
    let json = &rules[rules.find('[').unwrap()..=rules.find("\n  ]").unwrap() + 3];
    serde_json::from_str(json).expect("flow-style rules parse as JSON")
}

fn shipped_caps(model: &str) -> busbar_contract::ir::egress_prep::LaneCaps {
    crate::ir::lane_caps::resolve_lane_caps(Default::default(), &shipped_bedrock_rules(), model)
}

/// Item 8: the catalog turns adaptive thinking + native structured output on for the newest
/// Claude generations on Bedrock, native structured output alone for the 4.5/4.6 models AWS lists,
/// and nothing for any other model.
#[test]
fn item8_shipped_bedrock_catalog_declares_claude_lane_caps() {
    for newest in [
        "anthropic.claude-opus-4-7-v1:0",
        "us.anthropic.claude-opus-5-v1:0",
        "global.anthropic.claude-sonnet-5-20260101-v1:0",
        "us.anthropic.claude-fable-5-1-v1:0",
    ] {
        let caps = shipped_caps(newest);
        assert!(
            caps.anthropic_adaptive_thinking && caps.native_structured_output,
            "{newest}: {caps:?}"
        );
    }
    for listed in [
        "anthropic.claude-sonnet-4-5-20250929-v1:0",
        "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "anthropic.claude-opus-4-5-20251101-v1:0",
        "us.anthropic.claude-opus-4-6-v1",
    ] {
        let caps = shipped_caps(listed);
        assert!(
            caps.native_structured_output && !caps.anthropic_adaptive_thinking,
            "{listed}: {caps:?}"
        );
    }
    for other in [
        "anthropic.claude-sonnet-4-6",
        "anthropic.claude-3-7-sonnet-20250219-v1:0",
        "amazon.nova-pro-v1:0",
    ] {
        assert_eq!(
            shipped_caps(other),
            busbar_contract::ir::egress_prep::LaneCaps::NONE,
            "{other}"
        );
    }
}
