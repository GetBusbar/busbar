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

/// THE DEALT SECTION ALONE (the boot's stage 3g deal hands the plane `{pools: ...}`, no `models`):
/// its members are not judged against models the blob does not state, so a valid deployment is not
/// refused at boot; with `models` stated, an undefined member is still refused (the RED arm).
#[test]
fn a_pools_section_dealt_alone_names_no_unknown_model() {
    let dealt = json!({ "pools": { "op": { "members": [{ "model": "test-model" }] } } });
    Shaping::from_settings(&dealt).expect("the dealt section alone reads");
    let mut stated = dealt.clone();
    stated["models"] = json!({});
    assert!(Shaping::from_settings(&stated)
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

/// THE TRANSLATE CAP IS THE SETTINGS' (row 155): the cap a generation enforces is the
/// `limits.request_body_max_bytes` the kernel handed in the settings it was opened or refreshed
/// with, and the kernel's own 32 MiB default when it handed none.
#[test]
fn the_translate_cap_is_the_one_the_settings_carry_else_the_default() {
    let s = Shaping::from_settings(&json!({ "limits": { "request_body_max_bytes": 131072 } }))
        .expect("reads");
    assert_eq!(s.translate_cap(), 131_072);
    let s = Shaping::from_settings(&settings()).expect("reads");
    assert_eq!(
        s.translate_cap(),
        busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT
    );
    let s = Shaping::from_settings(&json!({})).expect("reads");
    assert_eq!(
        s.translate_cap(),
        busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT
    );
}

#[test]
fn the_glob_takes_prefix_suffix_and_middle_wildcards() {
    assert!(glob_match("gpt-*", "gpt-4o"));
    assert!(glob_match("*-mini", "o1-mini"));
    assert!(glob_match("a*c*e", "abcde"));
    assert!(!glob_match("a*c*e", "abde"));
    assert!(glob_match("exact", "exact") && !glob_match("exact", "exactly"));
}

/// LEGACY `crates/busbar-llm/src/engine/tests/attempt_timeout_precedence_tests.rs::effective_reasoning_member_override_wins`
/// (coverage map v2 row 43). 1.5.5: the pool member's `reasoning` override wins over the model's
/// flag in both directions (true over false AND false over true); a member with no override
/// inherits the model's flag, true or false; a pool or member with no candidate row uses the
/// model's flag.
///
/// RED: a member's `reasoning: false` stops beating a model's `reasoning: true` (the arm the
/// neighbouring test never drives), or a route with no member row stops reading the model's flag.
#[test]
fn effective_reasoning_member_override_wins() {
    let mut v = settings();
    // `claude` states `reasoning: true` at the model level; `quiet` turns it off in its pool only.
    v["pools"]["quiet"] = json!({ "members": [ { "model": "claude", "reasoning": false } ] });
    let s = Shaping::from_settings(&v).expect("reads");
    assert_eq!(
        s.reasoning("main", "gpt"),
        Some(true),
        "member true beats model false"
    );
    assert_eq!(
        s.reasoning("quiet", "claude"),
        Some(false),
        "member false beats model true"
    );
    assert_eq!(
        s.reasoning("main", "claude"),
        Some(true),
        "no member override inherits model true"
    );
    assert_eq!(
        s.reasoning("alt", "gpt"),
        Some(false),
        "no member override inherits model false"
    );
    assert_eq!(
        s.reasoning("alt", "claude"),
        Some(true),
        "a pool with no row for the member uses the model flag"
    );
    assert_eq!(
        s.reasoning("no-such-pool", "gpt"),
        Some(false),
        "no candidate row uses the model flag"
    );
    assert_eq!(
        s.reasoning("no-such-pool", "claude"),
        Some(true),
        "no candidate row uses the model flag"
    );
}

/// A MODEL'S OWN `protocol` OVERRIDES ITS PROVIDER'S (#51, THE DESIGN section 2, the BEDROCK-INVOKE ruling): the
/// model is spoken in the dialect it names, a sibling model on the same provider keeps the
/// provider's, and a dialect the plane does not serve is refused naming the model (fail-closed).
/// RED: a plane that reads only the provider's `protocol` writes the overriding model's requests
/// in `openai` and accepts an unknown override.
#[test]
fn a_models_protocol_overrides_its_providers_and_an_unknown_one_is_refused() {
    let mut v = settings();
    v["models"]["gpt-as-ant"] = json!({ "provider": "oai", "protocol": "anthropic" });
    let s = Shaping::from_settings(&v).expect("reads");
    assert_eq!(s.lane("gpt-as-ant").expect("the lane").dialect, "anthropic");
    assert_eq!(
        s.lane("gpt").expect("the sibling").dialect,
        "openai",
        "a model naming no protocol keeps its provider's"
    );
    let mut v = settings();
    v["models"]["gpt"]["protocol"] = json!("klingon");
    let refused = Shaping::from_settings(&v).unwrap_err();
    assert!(
        refused.contains("model 'gpt' uses unknown protocol 'klingon'"),
        "{refused}"
    );
}

/// AN EMPTY `model_capabilities` READS AS AN ABSENT ONE (row 155 B1b; coordinator ruling): the
/// kernel's resolved provider table now hands the plane `model_capabilities: []` where a catalog
/// entry states none, where it used to leave the key out. The plane reads the two the same way, so
/// every lane shapes its request exactly as before. RED: an empty rule list read differently from an
/// absent one (any lane field differing).
#[test]
fn an_empty_model_capabilities_reads_as_an_absent_one() {
    let absent = settings();
    let mut empty = settings();
    empty["providers"]["ant"]["model_capabilities"] = json!([]);
    let (absent, empty) = (
        Shaping::from_settings(&absent).expect("reads"),
        Shaping::from_settings(&empty).expect("reads"),
    );
    assert_eq!(
        absent.lane("claude"),
        empty.lane("claude"),
        "the same lane either way"
    );
}
