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

/// Item 12 (Q57): a `model_capabilities` rule's `reasoning_none` / `thinking_always_on` reach the
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
