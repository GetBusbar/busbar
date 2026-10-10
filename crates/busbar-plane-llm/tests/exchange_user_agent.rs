// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OWNER RULING Q10 (LLM-UA): the far end's `user-agent`. On a same-dialect route the caller's
//! passes through unchanged, and a caller that sent none gets the dialect's declared native-SDK
//! fingerprint, as 1.5.5 sent. On a translated route the plane writes the far dialect's declared
//! fingerprint, and no caller value reaches the far end.

use serde_json::json;

use busbar_plane_llm::exchange::arrive::arrive;
use busbar_plane_llm::exchange::attempt::{build, FarRequest};
use busbar_plane_llm::exchange::shaping::Shaping;

fn shaping() -> Shaping {
    Shaping::from_settings(&json!({
        "providers": {
            "oai": { "protocol": "openai", "base_url": "https://api.example" },
            "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" },
            "goo": { "protocol": "gemini", "base_url": "https://gemini.example" }
        },
        "models": {
            "gpt": { "provider": "oai" },
            "claude": { "provider": "ant", "default_max_tokens": 321 },
            "gem": { "provider": "goo", "upstream_model": "gemini-pro" }
        },
        "pools": { "p": { "members": ["gpt", "claude", "gem"] } }
    }))
    .expect("reads")
}

const CHAT: &str = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
const MESSAGES: &str =
    r#"{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;

fn far(target: &str, body: &str, caller_ua: Option<&'static str>, member: &str) -> FarRequest {
    let mut h: Vec<(&[u8], &[u8])> =
        vec![(b"content-type".as_slice(), b"application/json".as_slice())];
    if let Some(ua) = caller_ua {
        h.push((b"user-agent".as_slice(), ua.as_bytes()));
    }
    let a = arrive("POST", target, &h, body.as_bytes(), &()).expect("arrives");
    build(&a, &h, &shaping(), "p", member).expect("built")
}

fn user_agent(r: &FarRequest) -> Vec<&[u8]> {
    r.fields
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.as_slice())
        .collect()
}

#[test]
fn a_same_dialect_far_end_sees_exactly_the_caller_s_user_agent() {
    for (target, body, member) in [
        ("/v1/messages", MESSAGES, "claude"),
        ("/v1/chat/completions", CHAT, "gpt"),
    ] {
        let r = far(target, body, Some("curl/8.5.0"), member);
        assert_eq!(user_agent(&r), [b"curl/8.5.0".as_slice()], "{target}");
    }
}

#[test]
fn a_same_dialect_caller_that_sent_no_user_agent_carries_the_1_5_5_fingerprint() {
    for (target, body, member, fingerprint) in [
        (
            "/v1/messages",
            MESSAGES,
            "claude",
            "Anthropic/Python 0.39.0",
        ),
        ("/v1/chat/completions", CHAT, "gpt", "OpenAI/Python 1.54.0"),
    ] {
        let r = far(target, body, None, member);
        assert_eq!(user_agent(&r), [fingerprint.as_bytes()], "{target}");
    }
}

#[test]
fn a_translated_far_end_sees_the_far_dialect_s_fingerprint_never_the_caller_s() {
    for (target, body, member, fingerprint) in [
        (
            "/v1/chat/completions",
            CHAT,
            "claude",
            "Anthropic/Python 0.39.0",
        ),
        ("/v1/messages", MESSAGES, "gpt", "OpenAI/Python 1.54.0"),
        (
            "/v1/chat/completions",
            CHAT,
            "gem",
            "google-genai-sdk/0.8.0 gl-python/3.11",
        ),
    ] {
        for caller in [None, Some("curl/8.5.0")] {
            let r = far(target, body, caller, member);
            assert_eq!(
                user_agent(&r),
                [fingerprint.as_bytes()],
                "{target} -> {member}, caller {caller:?}"
            );
        }
    }
}
