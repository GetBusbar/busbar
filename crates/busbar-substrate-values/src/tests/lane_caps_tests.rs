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
