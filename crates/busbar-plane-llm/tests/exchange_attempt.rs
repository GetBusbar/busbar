// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One attempt's far-end request.

use serde_json::json;

use busbar_plane_llm::exchange::arrive::arrive;
use busbar_plane_llm::exchange::arrive::Arrived;
use busbar_plane_llm::exchange::attempt::*;
use busbar_plane_llm::exchange::shaping::Shaping;
use serde_json::Value;

fn shaping() -> Shaping {
    Shaping::from_settings(&json!({
        "providers": {
            "oai": { "protocol": "openai", "base_url": "https://api.example" },
            "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" },
            "goo": { "protocol": "gemini", "base_url": "https://gemini.example" },
            "fixed": { "protocol": "openai", "base_url": "https://x.example", "path": "/custom/chat" }
        },
        "models": {
            "gpt": { "provider": "oai" },
            "gpt-alias": { "provider": "oai", "upstream_model": "gpt-4o" },
            "claude": { "provider": "ant", "default_max_tokens": 321 },
            "gem": { "provider": "goo", "upstream_model": "gemini-pro" },
            "fixed": { "provider": "fixed" }
        },
        "pools": { "p": { "members": ["gpt", "claude"] } }
    }))
    .expect("reads")
}

fn head(pairs: &[(&'static str, &'static str)]) -> Vec<(&'static [u8], &'static [u8])> {
    pairs
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect()
}

fn arrived(target: &str, h: &[(&[u8], &[u8])], body: &str) -> Arrived {
    arrive("POST", target, h, body.as_bytes(), &()).expect("arrives")
}

fn field<'a>(r: &'a FarRequest, name: &str) -> Vec<&'a [u8]> {
    r.fields
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
        .collect()
}

#[test]
fn a_same_dialect_body_the_far_end_would_not_change_goes_out_as_the_callers_bytes() {
    let h = head(&[("content-type", "application/json")]);
    let body = r#"{"model":"gpt","messages":[{"role":"user","content":"hi"}]}"#;
    let a = arrived("/v1/chat/completions", &h, body);
    let r = build(&a, &h, &shaping(), "p", "gpt").expect("built");
    assert!(r.pristine);
    assert_eq!(
        r.body,
        body.as_bytes(),
        "byte for byte, whitespace and key order kept"
    );
    assert_eq!(r.verb, "POST");
    assert_eq!(r.target, "/v1/chat/completions");
}

#[test]
fn the_wire_model_is_written_when_it_differs() {
    let h = head(&[("content-type", "application/json")]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gpt-alias","messages":[]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "gpt-alias").expect("built");
    assert!(!r.pristine);
    let v: Value = busbar_plane_llm::codec::json::parse(&r.body).expect("json");
    assert_eq!(v["model"], "gpt-4o");
}

#[test]
fn a_cross_dialect_request_is_written_in_the_far_ends_dialect() {
    let h = head(&[("content-type", "application/json")]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"claude","messages":[{"role":"user","content":"hi"}]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "claude").expect("built");
    assert!(!r.pristine);
    assert_eq!(r.target, "/v1/messages");
    let v: Value = busbar_plane_llm::codec::json::parse(&r.body).expect("json");
    assert_eq!(v["model"], "claude");
    assert_eq!(
        v["max_tokens"], 321,
        "the lane's own default, the far end requires one"
    );
    assert_eq!(v["messages"][0]["role"], "user");
}

#[test]
fn a_same_dialect_caller_s_fields_all_go_out_but_the_governed_ones() {
    let h = head(&[
        ("content-type", "application/json"),
        ("anthropic-version", "2023-06-01"),
        ("anthropic-beta", "a"),
        ("anthropic-beta", "b"),
        ("X-Client-Trace", "abc"),
        ("authorization", "Bearer never-forwarded"),
        ("x-api-key", "never-forwarded"),
    ]);
    let a = arrived(
        "/v1/messages",
        &h,
        r#"{"model":"claude","max_tokens":5,"messages":[]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "claude").expect("built");
    let names: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "user-agent",
            "accept",
            "content-type",
            "anthropic-version",
            "anthropic-beta",
            "anthropic-beta",
            "x-client-trace"
        ],
        "busbar's native defaults the caller did not send, then every caller field but the credential"
    );
    assert_eq!(
        field(&r, "user-agent"),
        [b"Anthropic/Python 0.39.0".as_slice()],
        "a caller that sent no user-agent: the native client's (1.5.5's bytes)"
    );
    assert_eq!(field(&r, "accept"), [b"application/json".as_slice()]);
    assert_eq!(
        field(&r, "anthropic-beta"),
        [b"a".as_slice(), b"b".as_slice()]
    );
    assert_eq!(field(&r, "x-client-trace"), [b"abc".as_slice()]);
}

#[test]
fn the_caller_s_value_replaces_busbar_s_native_default() {
    let h = head(&[
        ("content-type", "application/json"),
        ("user-agent", "my-sdk/1.0"),
    ]);
    let a = arrived(
        "/v1/messages",
        &h,
        r#"{"model":"claude","max_tokens":5,"messages":[]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "claude").expect("built");
    assert_eq!(field(&r, "user-agent"), [b"my-sdk/1.0".as_slice()]);
}

#[test]
fn the_caller_s_tenant_selectors_never_go_out() {
    let h = head(&[
        ("content-type", "application/json"),
        ("OpenAI-Organization", "org-caller"),
        ("OpenAI-Project", "proj-caller"),
    ]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gpt","messages":[]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "gpt").expect("built");
    assert_eq!(field(&r, "openai-organization").len(), 0);
    assert_eq!(field(&r, "openai-project").len(), 0);
}

#[test]
fn a_translated_route_forwards_no_caller_field() {
    let h = head(&[
        ("content-type", "application/json"),
        ("anthropic-beta", "a"),
        ("openai-beta", "assistants=v2"),
        ("x-client-trace", "abc"),
    ]);
    let a = arrived(
        "/v1/messages",
        &h,
        r#"{"model":"claude","max_tokens":5,"messages":[]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "gpt").expect("built");
    let names: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["content-type", "user-agent", "accept"]);
    assert_eq!(
        field(&r, "user-agent"),
        [b"OpenAI/Python 1.54.0".as_slice()],
        "written in the far dialect, as its native client"
    );
}

#[test]
fn a_same_dialect_unknown_body_member_goes_out() {
    let h = head(&[("content-type", "application/json")]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gpt-alias","messages":[],"x_vendor_flag":true}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "gpt-alias").expect("built");
    let v: Value = busbar_plane_llm::codec::json::parse(&r.body).expect("json");
    assert_eq!(v["model"], "gpt-4o", "the mapped model");
    assert_eq!(v["x_vendor_flag"], true, "the unknown member, unchanged");
}

#[test]
fn a_translated_route_drops_a_member_the_far_dialect_cannot_carry() {
    let h = head(&[("content-type", "application/json")]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"claude","messages":[{"role":"user","content":"hi"}],"x_vendor_flag":true}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "claude").expect("built");
    let v: Value = busbar_plane_llm::codec::json::parse(&r.body).expect("json");
    assert!(v.get("x_vendor_flag").is_none());
}

#[test]
fn a_streamed_request_asks_a_far_end_that_reports_usage_only_when_asked() {
    let h = head(&[("content-type", "application/json")]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gpt","stream":true,"messages":[]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "gpt").expect("built");
    assert_eq!(
        r.body,
        br#"{"stream_options":{"include_usage":true},"model":"gpt","stream":true,"messages":[]}"#
    );
    assert_eq!(field(&r, "accept"), [b"text/event-stream".as_slice()]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gpt","stream":true,"stream_options":7,"messages":[]}"#,
    );
    let refused = build(&a, &h, &shaping(), "p", "gpt").expect_err("refused");
    assert_eq!(refused.status, 400);
    assert_eq!(refused.message, DETAIL_STREAM_OPTIONS_NOT_OBJECT);
}

#[test]
fn the_far_ends_path_is_its_dialects_own_or_the_providers_fixed_one() {
    let h = head(&[("content-type", "application/json")]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gem","stream":true,"messages":[{"role":"user","content":"x"}]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "gem").expect("built");
    assert!(
        r.target.contains("gemini-pro") && r.target.contains("streamGenerateContent"),
        "{}",
        r.target
    );
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"fixed","messages":[]}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "fixed").expect("built");
    assert_eq!(r.target, "/custom/chat");
}

#[test]
fn a_path_outside_the_unreserved_set_is_percent_encoded_on_the_wire_and_twice_for_a_signature() {
    assert_eq!(
        wire_and_canonical_path("/model/a.b-c_d~e/converse"),
        (
            "/model/a.b-c_d~e/converse".to_string(),
            "/model/a.b-c_d~e/converse".to_string()
        )
    );
    assert_eq!(
        wire_and_canonical_path("/model/x:0/converse?q=1"),
        (
            "/model/x%3A0/converse?q=1".to_string(),
            "/model/x%253A0/converse".to_string()
        )
    );
}

#[test]
fn a_member_the_generation_does_not_hold_is_the_callers_500() {
    let h = head(&[("content-type", "application/json")]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gpt","messages":[]}"#,
    );
    let refused = build(&a, &h, &shaping(), "p", "nobody").expect_err("refused");
    assert_eq!((refused.status, refused.envelope), (500, "openai"));
    assert_eq!(refused.message, DETAIL_INTERNAL_ERROR);
}

#[test]
fn the_pristine_ask_splices_after_the_opening_brace_and_falls_back_to_a_parse() {
    let out = try_inject_stream_include_usage_pristine(br#" {"a":1}"#.to_vec()).expect("asked");
    assert_eq!(out, br#" {"stream_options":{"include_usage":true},"a":1}"#);
    let out = try_inject_stream_include_usage_pristine(br#"{"stream_options":null}"#.to_vec())
        .expect("asked");
    assert_eq!(out, br#"{"stream_options":{"include_usage":true}}"#);
    let out = try_inject_stream_include_usage_pristine(b"[1]".to_vec()).expect("unchanged");
    assert_eq!(out, b"[1]");
    assert!(try_inject_stream_include_usage(br#"{"stream_options":"x"}"#.to_vec()).is_err());
}

/// BUSBAR IS INVISIBLE TO UPSTREAMS, THE URL TOO: a same-dialect attempt carries the caller's own
/// query, in its order and spelling, but the dialect's governed credential parameters and the ones
/// the target already sets (busbar's own stream framing); a translated attempt carries none.
#[test]
fn the_callers_query_goes_out_on_a_same_dialect_attempt() {
    assert_eq!(
        with_caller_query(
            "gemini",
            "/v1beta/models/m:streamGenerateContent?alt=sse",
            "key=secret&alt=json&trace=a%2Fb"
        ),
        Some("/v1beta/models/m:streamGenerateContent?alt=sse&trace=a%2Fb".to_string())
    );
    assert_eq!(
        with_caller_query("openai", "/v1/chat/completions", "trace=1&beta=true"),
        Some("/v1/chat/completions?trace=1&beta=true".to_string())
    );
    assert_eq!(with_caller_query("gemini", "/x", "key=secret"), None);
    let h = head(&[("content-type", "application/json")]);
    let a = arrive(
        "POST",
        "/v1/messages?beta=true",
        &h,
        br#"{"model":"claude","max_tokens":5,"messages":[]}"#,
        &(),
    )
    .expect("arrives");
    let same = build(&a, &h, &shaping(), "p", "claude").expect("built");
    assert_eq!(same.target, "/v1/messages?beta=true");
    let crossed = build(&a, &h, &shaping(), "p", "gpt").expect("built");
    assert_eq!(crossed.target, "/v1/chat/completions");
}

/// A signed dialect's attempt carries no caller query until its signer signs the canonical query
/// (never a query the signature omits).
#[test]
fn a_signed_dialects_attempt_carries_no_query_yet() {
    assert_eq!(
        with_caller_query("bedrock", "/model/m/converse", "trace=1"),
        None
    );
}
