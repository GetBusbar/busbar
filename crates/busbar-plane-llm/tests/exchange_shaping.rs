// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shaping tables, read from the settings object.

use serde_json::json;

use busbar_contract::ir::egress_prep::MaxOutputKey;
use busbar_plane_llm::exchange::shaping::*;
use serde_json::Value;

fn settings() -> Value {
    json!({
        "providers": {
            "oai": { "protocol": "openai", "base_url": "https://api.example", "error_map": { "x": "y" },
                     "max_output_key": "max_completion_tokens",
                     "model_capabilities": [ { "models": ["o1*"], "reasoning_none": true } ] },
            "ant": { "base_url": "https://anthropic.example", "path_base": "/v9" }
        },
        "models": {
            "gpt": { "provider": "oai", "upstream_model": "o1-mini", "default_max_tokens": 100 },
            "claude": { "provider": "ant", "reasoning": true, "prompt_caching": true }
        },
        "pools": {
            "upstream_credentials": "own",
            "main": { "members": [ "claude", { "model": "gpt", "reasoning": true, "context_max": 8000 } ] },
            "alt": { "members": [ { "model": "gpt", "context_max": 8000 } ] }
        },
        "limits": { "default_max_tokens": 777, "reasoning_effort_budgets": { "high": 99 } }
    })
}

#[test]
fn a_lane_carries_the_fields_that_shape_its_request() {
    let s = Shaping::from_settings(&settings()).expect("reads");
    let gpt = s.lane("gpt").expect("gpt");
    assert_eq!(gpt.dialect, "openai");
    assert_eq!(gpt.wire_model(), "o1-mini");
    assert_eq!(gpt.default_max_tokens, Some(100));
    assert_eq!(gpt.context_max, Some(8000));
    assert_eq!(gpt.caps.max_output_key, MaxOutputKey::MaxCompletionTokens);
    assert!(gpt.caps.reasoning_none, "the rule matches the WIRE model");
    assert_eq!(gpt.error_map.get("x").map(String::as_str), Some("y"));
    let claude = s.lane("claude").expect("claude");
    assert_eq!(claude.dialect, "anthropic", "the default protocol");
    assert_eq!(claude.path_base.as_deref(), Some("/v9"));
    assert!(claude.reasoning && claude.prompt_caching);
    assert_eq!(s.default_max_tokens, 777);
    assert_eq!(s.reasoning_budgets, [1024, 4096, 8192, 99]);
}

#[test]
fn a_member_s_own_reasoning_wins_in_its_pool_only() {
    let s = Shaping::from_settings(&settings()).expect("reads");
    assert_eq!(s.reasoning("main", "gpt"), Some(true));
    assert_eq!(s.reasoning("alt", "gpt"), Some(false));
    assert_eq!(s.reasoning("main", "claude"), Some(true));
    assert_eq!(s.pools.len(), 2, "a reserved key is not a pool");
}

#[test]
fn a_generation_the_plane_cannot_serve_is_refused() {
    let mut v = settings();
    v["models"]["x"] = json!({ "provider": "nobody" });
    assert!(Shaping::from_settings(&v)
        .unwrap_err()
        .contains("unknown provider"));
    let mut v = settings();
    v["providers"]["oai"]["protocol"] = json!("klingon");
    assert!(Shaping::from_settings(&v)
        .unwrap_err()
        .contains("unknown protocol"));
    let mut v = settings();
    v["pools"]["alt"]["members"] = json!([{ "model": "gpt", "context_max": 9000 }]);
    assert!(Shaping::from_settings(&v)
        .unwrap_err()
        .contains("conflicting context_max"));
    let mut v = settings();
    v["pools"]["alt"]["members"] = json!(["ghost"]);
    assert!(Shaping::from_settings(&v)
        .unwrap_err()
        .contains("unknown model"));
}

#[test]
fn empty_settings_are_an_empty_generation_with_the_defaults() {
    let s = Shaping::from_settings(&json!({})).expect("reads");
    assert!(s.lanes.is_empty());
    assert_eq!(s.default_max_tokens, DEFAULT_MAX_TOKENS);
    assert_eq!(s.reasoning_budgets, DEFAULT_REASONING_BUDGETS);
}

#[test]
fn the_glob_takes_prefix_suffix_and_middle_wildcards() {
    assert!(glob_match("gpt-*", "gpt-4o"));
    assert!(glob_match("*-mini", "o1-mini"));
    assert!(glob_match("a*c*e", "abcde"));
    assert!(!glob_match("a*c*e", "abde"));
    assert!(glob_match("exact", "exact") && !glob_match("exact", "exactly"));
}
