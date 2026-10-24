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

/// The codec host these tests hand the plane: the OS CSPRNG and the system clock in whole seconds,
/// read the way the kernel's host reads them.
struct TestHost;

impl busbar_contract::codec::CodecHost for TestHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        getrandom::fill(out).is_ok()
    }

    fn wall_clock_now(&self) -> Option<u64> {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }
}

/// The handle every codec call here is handed.
const HOST: &dyn busbar_contract::codec::CodecHost = &TestHost;

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
    build(HOST, &a, &h, &shaping(), "p", member).expect("built")
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

/// One member per far dialect, so every dialect's fingerprint is read off a request the plane builds.
fn every_dialect() -> Shaping {
    Shaping::from_settings(&json!({
        "providers": {
            "oai": { "protocol": "openai", "base_url": "https://api.example" },
            "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" },
            "goo": { "protocol": "gemini", "base_url": "https://gemini.example" },
            "bed": { "protocol": "bedrock", "base_url": "https://bedrock.example" },
            "res": { "protocol": "responses", "base_url": "https://responses.example" },
            "coh": { "protocol": "cohere", "base_url": "https://cohere.example" }
        },
        "models": {
            "gpt": { "provider": "oai" },
            "claude": { "provider": "ant" },
            "gem": { "provider": "goo", "upstream_model": "gemini-pro" },
            "bedrock-claude": { "provider": "bed", "upstream_model": "anthropic.claude-3" },
            "resp": { "provider": "res" },
            "command": { "provider": "coh" }
        },
        "pools": { "p": { "members": ["gpt", "claude", "gem", "bedrock-claude", "resp", "command"] } }
    }))
    .expect("reads")
}

/// LEGACY `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_egress_ua_versions_are_pinned_and_present`
/// (coverage map v2 row 325). 1.5.5: every egress request carries the pinned native-SDK
/// `user-agent` of its far dialect, as a golden literal: anthropic `Anthropic/Python 0.39.0`,
/// openai and responses `OpenAI/Python 1.54.0`, gemini `google-genai-sdk/0.8.0 gl-python/3.11`,
/// bedrock `Boto3/1.35.0 md/Botocore#1.35.0`, cohere `cohere-python/5.11.0`, and a far end no
/// declaration names `okhttp/4.12.0`. None is ever empty or versionless, and the two Stainless
/// Python SDKs share the `<Title>/Python <ver>` grammar.
///
/// RED: any far dialect's request goes out with another (or no) `user-agent`, the foreign default
/// moves, or a pinned version string is edited without touching this table.
#[test]
fn every_dialects_egress_user_agent_version_is_pinned_and_present() {
    let s = every_dialect();
    let pinned = [
        ("claude", "Anthropic/Python 0.39.0"),
        ("gpt", "OpenAI/Python 1.54.0"),
        ("resp", "OpenAI/Python 1.54.0"),
        ("gem", "google-genai-sdk/0.8.0 gl-python/3.11"),
        ("bedrock-claude", "Boto3/1.35.0 md/Botocore#1.35.0"),
        ("command", "cohere-python/5.11.0"),
    ];
    // An anthropic caller that sent no user-agent: every far end below sees its own fingerprint,
    // the same-dialect one included (1.5.5 sent the native fingerprint to a UA-less caller's far end).
    let head: Vec<(&[u8], &[u8])> =
        vec![(b"content-type".as_slice(), b"application/json".as_slice())];
    let arrived = arrive("POST", "/v1/messages", &head, MESSAGES.as_bytes(), &()).expect("arrives");
    for (member, want) in pinned {
        let r = build(HOST, &arrived, &head, &s, "p", member).expect("built");
        assert_eq!(
            user_agent(&r),
            [want.as_bytes()],
            "{member} egress UA drifted from the pinned native-SDK string"
        );
    }
    // The foreign far end (a dialect no declaration names) still gets a present, plausible UA.
    assert_eq!(
        busbar_contract::protocol::EGRESS_UA_DEFAULT,
        "okhttp/4.12.0",
        "the foreign/default egress UA drifted from the pinned literal"
    );
    // Every declaration states its pinned literal, so no far dialect can fall to the default.
    for d in busbar_plane_llm::codec::DECLS {
        let want = match d.name {
            "anthropic" => "Anthropic/Python 0.39.0",
            "openai" | "responses" => "OpenAI/Python 1.54.0",
            "gemini" => "google-genai-sdk/0.8.0 gl-python/3.11",
            "bedrock" => "Boto3/1.35.0 md/Botocore#1.35.0",
            "cohere" => "cohere-python/5.11.0",
            other => panic!("a dialect this table does not pin: {other}"),
        };
        assert_eq!(d.egress_user_agent, want, "{}", d.name);
    }
    let every: Vec<&str> = pinned
        .iter()
        .map(|(_, ua)| *ua)
        .chain([busbar_contract::protocol::EGRESS_UA_DEFAULT])
        .collect();
    for ua in every {
        assert!(!ua.is_empty(), "an egress UA must never be empty");
        assert!(
            ua.chars().any(|ch| ch.is_ascii_digit()),
            "an egress UA must carry a version number: {ua}"
        );
    }
    for ua in ["Anthropic/Python 0.39.0", "OpenAI/Python 1.54.0"] {
        let (title, rest) = ua.split_once('/').expect("Python-SDK UA contains a '/'");
        assert!(
            title
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_uppercase()),
            "Stainless Python SDK UA must start with a capitalized Title: {ua}"
        );
        assert!(
            rest.starts_with("Python "),
            "Stainless Python SDK UA must be `<Title>/Python <ver>`: {ua}"
        );
    }
}
