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
            "ant-key": { "protocol": "anthropic", "base_url": "https://az.example", "auth": "api-key" },
            "ant-bearer": { "protocol": "anthropic", "base_url": "https://b.example", "auth": "bearer" },
            "goo": { "protocol": "gemini", "base_url": "https://gemini.example" },
            "fixed": { "protocol": "openai", "base_url": "https://x.example", "path": "/custom/chat" }
        },
        "models": {
            "gpt": { "provider": "oai" },
            "gpt-alias": { "provider": "oai", "upstream_model": "gpt-4o" },
            "claude": { "provider": "ant", "default_max_tokens": 321 },
            "claude-key": { "provider": "ant-key", "default_max_tokens": 321 },
            "claude-bearer": { "provider": "ant-bearer", "default_max_tokens": 321 },
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
    // Only the governed member moves: key order, spacing and number spelling stay the caller's.
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"z":1.50, "model":"gpt-alias","messages":[],"a":{"y":1,"x":2}}"#,
    );
    let r = build(&a, &h, &shaping(), "p", "gpt-alias").expect("built");
    assert_eq!(
        r.body,
        br#"{"z":1.50, "model":"gpt-4o","messages":[],"a":{"y":1,"x":2}}"#
    );
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
            "anthropic-version",
            "content-type",
            "user-agent",
            "accept",
            "anthropic-beta",
            "anthropic-beta",
            "x-client-trace"
        ],
        "busbar's own fields at their positions (the caller's values where it sent one), then every \
         other caller field but the credential, as 1.5.5's header map laid them"
    );
    assert_eq!(
        field(&r, "user-agent"),
        [b"Anthropic/Python 0.39.0".as_slice()],
        "a caller that sent no user-agent: the native client's (1.5.5's bytes, Q10)"
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
fn the_usage_ask_is_a_splice_after_the_opening_brace_or_in_place() {
    let out = try_inject_stream_include_usage(br#" {"a":1}"#.to_vec()).expect("asked");
    assert_eq!(out, br#" {"stream_options":{"include_usage":true},"a":1}"#);
    let out =
        try_inject_stream_include_usage(br#"{"stream_options":null}"#.to_vec()).expect("asked");
    assert_eq!(out, br#"{"stream_options":{"include_usage":true}}"#);
    let out = try_inject_stream_include_usage(br#"{"z":1, "stream_options":{"b":2}}"#.to_vec())
        .expect("asked");
    assert_eq!(
        out,
        br#"{"z":1, "stream_options":{"include_usage":true,"b":2}}"#
    );
    let out = try_inject_stream_include_usage(b"[1]".to_vec()).expect("unchanged");
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

/// A path-model same-dialect relay sends the caller's bytes: the `model` and `stream` the arrival
/// carried for routing come back out by byte splices, so key order, spacing and a member busbar has
/// never heard of all reach the far end as the caller wrote them (DIALECT FIDELITY).
#[test]
fn a_path_model_same_dialect_request_reaches_the_far_end_as_the_caller_wrote_it() {
    let h = head(&[("content-type", "application/json")]);
    let body = "{ \"zz_never_heard_of\": {\"b\":1,\"a\":2},\n  \"contents\": [ {\"parts\":[{\"text\":\"hi\"}]} ], \"n\": 1.50 }";
    let a = arrive(
        "POST",
        "/v1beta/models/gemini-pro:streamGenerateContent?alt=sse",
        &h,
        body.as_bytes(),
        &(),
    )
    .expect("arrives");
    let r = build(&a, &h, &shaping(), "p", "gem").expect("built");
    assert_eq!(String::from_utf8_lossy(&r.body), body);
}

/// A conversation history carrying a `custom` tool call (a type the IR does not model) is relayed
/// byte-identical within one dialect.
#[test]
fn a_history_with_a_custom_tool_call_relays_byte_identical() {
    let h = head(&[("content-type", "application/json")]);
    let body = r#"{"model":"gpt","messages":[{"role":"user","content":"go"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_c","type":"custom","custom":{"name":"grammar","input":"x = 1"}}]},{"role":"tool","tool_call_id":"call_c","content":"ok"}],"tools":[{"type":"custom","custom":{"name":"grammar"}}]}"#;
    let a = arrived("/v1/chat/completions", &h, body);
    let r = build(&a, &h, &shaping(), "p", "gpt").expect("built");
    assert_eq!(String::from_utf8_lossy(&r.body), body);
}

/// TENANT SELECTORS COME FROM BUSBAR'S CONFIG: a provider's `organization` / `project` ride every
/// far request under the headers its dialect declares, and a caller's own never do.
#[test]
fn the_providers_tenant_goes_out_and_the_callers_does_not() {
    let shaping = Shaping::from_settings(&json!({
        "providers": {
            "oai": {
                "protocol": "openai",
                "base_url": "https://api.example",
                "organization": "org-cfg",
                "project": "proj-cfg"
            }
        },
        "models": { "gpt": { "provider": "oai" } },
        "pools": { "p": { "members": ["gpt"] } }
    }))
    .expect("reads");
    let h = head(&[
        ("content-type", "application/json"),
        ("openai-organization", "org-caller"),
    ]);
    let a = arrived(
        "/v1/chat/completions",
        &h,
        r#"{"model":"gpt","messages":[]}"#,
    );
    let r = build(&a, &h, &shaping, "p", "gpt").expect("built");
    assert_eq!(field(&r, "openai-organization"), [b"org-cfg".as_slice()]);
    assert_eq!(field(&r, "openai-project"), [b"proj-cfg".as_slice()]);
}

/// THE DIALECT'S STATIC FIELDS (ARCHITECT SD-3 (1), "anthropic S2-a": anthropic declares
/// `anthropic-version`, written verbatim; byte-identical upstream requests): a caller that sends no
/// field of its own still reaches an anthropic far end with the pinned version and the native
/// client's user-agent, same-dialect or translated; under an operator's `auth: api-key` override,
/// whose scheme declares no static field, none goes out; `auth: bearer` is the dialect's own scheme
/// and keeps it. A same-dialect caller's own value replaces it.
#[test]
fn no_client_header_leaves_egress_unchanged() {
    let none = head(&[]);
    let body = r#"{"model":"claude","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;
    let a = arrived("/v1/messages", &none, body);
    let r = build(&a, &none, &shaping(), "p", "claude").expect("built");
    assert_eq!(field(&r, "anthropic-version"), [b"2023-06-01".as_slice()]);
    assert_eq!(
        field(&r, "user-agent"),
        [b"Anthropic/Python 0.39.0".as_slice()]
    );
    let names: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["anthropic-version", "content-type", "user-agent", "accept"]
    );

    let openai = r#"{"model":"claude","messages":[{"role":"user","content":"hi"}]}"#;
    let a = arrived("/v1/chat/completions", &none, openai);
    let r = build(&a, &none, &shaping(), "p", "claude").expect("built");
    assert_eq!(
        field(&r, "anthropic-version"),
        [b"2023-06-01".as_slice()],
        "a translated route into anthropic carries it too"
    );

    let a = arrived("/v1/messages", &none, &body.replace("claude", "claude-key"));
    let r = build(&a, &none, &shaping(), "p", "claude-key").expect("built");
    assert!(
        field(&r, "anthropic-version").is_empty(),
        "an api-key override declares no static field"
    );
    let a = arrived(
        "/v1/messages",
        &none,
        &body.replace("claude", "claude-bearer"),
    );
    let r = build(&a, &none, &shaping(), "p", "claude-bearer").expect("built");
    assert_eq!(field(&r, "anthropic-version"), [b"2023-06-01".as_slice()]);

    let own = head(&[("anthropic-version", "2024-01-01")]);
    let a = arrived("/v1/messages", &own, body);
    let r = build(&a, &own, &shaping(), "p", "claude").expect("built");
    assert_eq!(
        field(&r, "anthropic-version"),
        [b"2024-01-01".as_slice()],
        "the same-dialect caller's own value wins"
    );

    let a = arrived(
        "/v1/chat/completions",
        &none,
        &openai.replace("claude", "gpt"),
    );
    let r = build(&a, &none, &shaping(), "p", "gpt").expect("built");
    assert!(
        field(&r, "anthropic-version").is_empty(),
        "openai declares none"
    );
}

/// THE PREVIOUS RELEASE'S HEADER-MAP ORDER (oracle `egress.auth|cred-identity|*`, `route.529|*`): a
/// same-dialect caller's own fields lie over busbar's as a header map lays them, one position per
/// name: a name busbar writes (its static field, `content-type`, `user-agent`, `accept`) keeps
/// busbar's position and takes the caller's value, a new name is appended in the caller's order,
/// and a repeated name keeps every value at its position.
#[test]
fn a_same_dialect_callers_fields_keep_busbars_positions() {
    let h = head(&[
        ("user-agent", "Anthropic/Python 0.39.0"),
        ("accept", "application/json"),
        ("anthropic-version", "2023-06-01"),
        ("content-type", "application/json"),
        ("x-trace", "a"),
        ("x-trace", "b"),
    ]);
    let body = r#"{"model":"claude","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;
    let a = arrived("/v1/messages", &h, body);
    let r = build(&a, &h, &shaping(), "p", "claude").expect("built");
    let names: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "anthropic-version",
            "content-type",
            "user-agent",
            "accept",
            "x-trace",
            "x-trace"
        ]
    );
    assert_eq!(field(&r, "x-trace"), [b"a".as_slice(), b"b".as_slice()]);
}
