// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The far-end request cases the retired engine crate's tests pinned, ported onto the plane's own
//! `build` (and the relay, splice and strip it composes): the output cap a far end requires, the
//! per-dialect target, `accept` and `user-agent` 1.5.5 sent, the controls a far dialect cannot
//! carry, the per-far-end reshapes, the router keys that never reach a far end, the usage opt-in
//! splice, and the multi-candidate and stop-list degrades. Each test cites the legacy test it ports.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use busbar_plane_llm::exchange::arrive::{arrive, Arrived};
use busbar_plane_llm::exchange::attempt::*;
use busbar_plane_llm::exchange::shaping::{FarShape, Shaping};

/// The Vertex AI path base a Claude-on-Vertex provider names.
const VERTEX_BASE: &str = "/v1/projects/p/locations/us-central1/publishers/anthropic/models";

/// One far end per dialect (each model named `m-<dialect>`, as the 1.5.5 oracle named its lanes),
/// and the provider shapes the reshape cases need.
fn shaping() -> Shaping {
    Shaping::from_settings(&json!({
        "providers": {
            "oai": { "protocol": "openai" },
            "ant": { "protocol": "anthropic" },
            "ant-native": { "protocol": "anthropic", "native_structured_output": true },
            "goo": { "protocol": "gemini" },
            "bed": { "protocol": "bedrock" },
            "coh": { "protocol": "cohere" },
            "rsp": { "protocol": "responses" },
            "vertex": { "protocol": "anthropic", "path_base": VERTEX_BASE },
            "azure": {
                "protocol": "openai",
                "path": "/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01"
            }
        },
        "models": {
            "m-openai": { "provider": "oai" },
            "m-anthropic": { "provider": "ant" },
            "m-anthropic-1234": { "provider": "ant", "upstream_model": "glm-4.5", "default_max_tokens": 1234 },
            "claude-opus-5": { "provider": "ant-native" },
            "m-gemini": { "provider": "goo" },
            "m-bedrock": { "provider": "bed" },
            "m-cohere": { "provider": "coh" },
            "m-responses": { "provider": "rsp" },
            "claude-3-5-sonnet": { "provider": "vertex" },
            "gpt-4o": { "provider": "azure" },
            "text-embedding-004": { "provider": "goo" }
        },
        "pools": { "p": { "members": ["m-openai"] } }
    }))
    .expect("reads")
}

fn json_head() -> Vec<(&'static [u8], &'static [u8])> {
    vec![(b"content-type".as_slice(), b"application/json".as_slice())]
}

fn arrived(target: &str, body: &Value) -> Arrived {
    let bytes = serde_json::to_vec(body).expect("serializes");
    arrive("POST", target, &json_head(), &bytes, &())
        .unwrap_or_else(|d| panic!("{target}: refused {d:?}"))
}

/// One attempt for `member`, the caller's `body` arriving at `target`.
fn far(target: &str, body: &Value, member: &str) -> FarRequest {
    build(
        &arrived(target, body),
        &json_head(),
        &shaping(),
        "p",
        member,
    )
    .unwrap_or_else(|a| panic!("{target} -> {member}: answered {a:?}"))
}

fn sent(r: &FarRequest) -> Value {
    busbar_plane_llm::codec::json::parse(&r.body).expect("the far body is JSON")
}

fn field<'a>(r: &'a FarRequest, name: &str) -> Vec<&'a [u8]> {
    r.fields
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
        .collect()
}

fn chat(extra: Value) -> Value {
    let mut v = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    if let (Some(o), Value::Object(e)) = (v.as_object_mut(), extra) {
        o.extend(e);
    }
    v
}

const OPENAI: &str = "/v1/chat/completions";

// ── the output cap a far end requires ───────────────────────────────────────────────────────────

/// An OpenAI request that omits `max_tokens`, sent to a far end that requires one, carries the
/// global fallback when the lane states no default.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_openai_omits_max_tokens_injects_fallback_for_anthropic`.
#[test]
fn an_omitted_max_tokens_reaches_a_far_end_that_requires_one_as_the_fallback() {
    let r = far(OPENAI, &chat(json!({})), "m-anthropic");
    assert_eq!(
        sent(&r)["max_tokens"].as_u64(),
        Some(u64::from(
            busbar_plane_llm::exchange::shaping::DEFAULT_MAX_TOKENS
        )),
        "{}",
        sent(&r)
    );
    assert_eq!(
        busbar_plane_llm::exchange::shaping::DEFAULT_MAX_TOKENS,
        4096
    );
}

/// The lane's own `default_max_tokens` replaces the fallback.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_openai_omits_max_tokens_uses_configured_lane_default`.
#[test]
fn an_omitted_max_tokens_takes_the_lanes_own_default() {
    let r = far(OPENAI, &chat(json!({})), "m-anthropic-1234");
    assert_eq!(sent(&r)["max_tokens"].as_u64(), Some(1234), "{}", sent(&r));
}

/// A caller's own `max_tokens` survives over the lane's default.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_openai_explicit_max_tokens_preserved_over_lane_default`.
#[test]
fn a_callers_max_tokens_survives_over_the_lanes_default() {
    let r = far(OPENAI, &chat(json!({"max_tokens": 7})), "m-anthropic-1234");
    assert_eq!(sent(&r)["max_tokens"].as_u64(), Some(7), "{}", sent(&r));
}

// ── what 1.5.5 sent each far dialect: the target, `accept` and `user-agent` ──────────────────────

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

/// The far request 1.5.5 recorded for an openai caller of a `far` lane: its path, `accept` and
/// `user-agent`; `None` when no cell records the pair.
fn recorded(far: &str, stream: bool) -> Option<(String, String, String)> {
    let cell = format!(
        "llm__openai__{far}__request__ok{}.json",
        if stream { "_stream" } else { "" }
    );
    let text = std::fs::read_to_string(golden().join(cell)).ok()?;
    let v: Value = serde_json::from_str(&text).expect("a recording is JSON");
    let e = &v["effects"]["egress"][0];
    let s = |p: &str| e.pointer(p).and_then(Value::as_str).map(str::to_string);
    Some((
        s("/path")?,
        s("/headers/accept")?,
        s("/headers/user-agent")?,
    ))
}

/// Every far dialect is sent the target its own dialect composes for the wire model and the stream
/// intent (path-encoded for the wire), the `accept` its native client sends (bedrock's event stream
/// when streaming, JSON otherwise; an event stream for every other dialect when streaming), and its
/// native client's pinned `user-agent`, for a stream and a single answer: each equal to what 1.5.5
/// sent where the oracle recorded the pair.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/egress_target_tests.rs::egress_targets_match_reference_composition_all_protocols`,
/// `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_egress_accept_matches_native_sdk`
/// and `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_egress_ua_versions_are_pinned_and_present`.
#[test]
fn every_far_dialect_is_sent_its_native_target_accept_and_user_agent() {
    let ua = |d: &str| match d {
        "anthropic" => "Anthropic/Python 0.39.0",
        "openai" | "responses" => "OpenAI/Python 1.54.0",
        "gemini" => "google-genai-sdk/0.8.0 gl-python/3.11",
        "bedrock" => "Boto3/1.35.0 md/Botocore#1.35.0",
        _ => "cohere-python/5.11.0",
    };
    let accept = |d: &str, stream: bool| match (d, stream) {
        ("bedrock", true) => "application/vnd.amazon.eventstream",
        (_, true) => "text/event-stream",
        (_, false) => "application/json",
    };
    let s = shaping();
    let mut pinned = 0;
    for d in SIX {
        let member = format!("m-{d}");
        for stream in [false, true] {
            let r = far(OPENAI, &chat(json!({"stream": stream})), &member);
            let lane = s.lane(&member).expect("the lane");
            let op = arrived(OPENAI, &chat(json!({"stream": stream}))).operation;
            let composed = upstream_path(lane, op, stream).expect("a path");
            assert_eq!(
                r.target,
                wire_and_canonical_path(&composed).0,
                "{d} stream={stream}: the target is the dialect's own, wire-encoded"
            );
            assert_eq!(
                field(&r, "accept"),
                [accept(d, stream).as_bytes()],
                "{d} stream={stream}"
            );
            assert_eq!(
                field(&r, "user-agent"),
                [ua(d).as_bytes()],
                "{d} stream={stream}"
            );
            if let Some((path, rec_accept, rec_ua)) = recorded(d, stream) {
                pinned += 1;
                assert_eq!(r.target, path, "{d} stream={stream}: 1.5.5's path");
                assert_eq!(
                    field(&r, "accept"),
                    [rec_accept.as_bytes()],
                    "{d} stream={stream}"
                );
                assert_eq!(
                    field(&r, "user-agent"),
                    [rec_ua.as_bytes()],
                    "{d} stream={stream}"
                );
            }
        }
    }
    assert!(pinned >= 11, "the oracle's cells were read: {pinned}");
    // Every native user-agent carries a version number, and the two Stainless-generated Python
    // clients share the `<Title>/Python <ver>` grammar.
    for d in SIX {
        assert!(ua(d).chars().any(|c| c.is_ascii_digit()), "{d}");
    }
    for u in [ua("anthropic"), ua("openai")] {
        let (title, rest) = u.split_once('/').expect("a slash");
        assert!(title.starts_with(|c: char| c.is_ascii_uppercase()), "{u}");
        assert!(rest.starts_with("Python "), "{u}");
    }
}

/// A far end of no dialect the plane speaks is never written to (the plane refuses to open over it),
/// so no far request goes out without a declared `accept` and `user-agent`; the defaults a far end
/// with no declaration would be written with are a plausible native pair, never absent.
///
/// Ports the unknown-dialect arms of legacy
/// `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_egress_accept_matches_native_sdk`
/// and `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_egress_ua_versions_are_pinned_and_present`.
#[test]
fn a_far_end_of_no_known_dialect_is_never_written_and_the_defaults_are_plausible() {
    let refused = Shaping::from_settings(&json!({
        "providers": { "x": { "protocol": "mystery" } },
        "models": { "m": { "provider": "x" } }
    }))
    .expect_err("an unknown dialect is refused");
    assert!(refused.contains("unknown protocol"), "{refused}");
    assert_eq!(
        busbar_contract::protocol::EGRESS_UA_DEFAULT,
        "okhttp/4.12.0"
    );
    assert_eq!(
        busbar_contract::protocol::TEXT_EVENT_STREAM,
        "text/event-stream"
    );
    assert_eq!(
        busbar_contract::protocol::APPLICATION_JSON,
        "application/json"
    );
}

/// A provider's full-path override carrying a query is kept verbatim on the wire, and the canonical
/// (signed) form carries no query.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/egress_target_tests.rs::egress_targets_honor_azure_path_override_with_query`.
#[test]
fn a_path_override_with_a_query_is_kept_verbatim() {
    let path = "/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01";
    for stream in [false, true] {
        let r = far(OPENAI, &chat(json!({"stream": stream})), "gpt-4o");
        assert_eq!(r.target, path, "stream={stream}");
    }
    assert_eq!(
        wire_and_canonical_path(path),
        (
            path.to_string(),
            "/openai/deployments/gpt-4o/chat/completions".to_string()
        )
    );
}

// ── the controls a far dialect cannot carry ─────────────────────────────────────────────────────

/// `response_format` on a default anthropic lane is translated to forced tool use, not dropped: the
/// request goes out, carries no bare `response_format`, and names no dropped `response_format`.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/egress_dropped_controls_audit_tests.rs::openai_to_anthropic_response_format_forwards_and_translates_not_dropped`
/// (the door writes one audit row per dropped control:
/// `serve_door::the_pools_door_audits_a_control_the_far_dialect_cannot_carry`).
#[test]
fn a_response_format_crossing_to_anthropic_is_translated_not_dropped() {
    let r = far(
        OPENAI,
        &chat(json!({"response_format": {"type": "json_object"}})),
        "m-anthropic",
    );
    let v = sent(&r);
    assert!(v.get("response_format").is_none(), "{v}");
    assert_eq!(
        v.pointer("/tool_choice/name"),
        Some(&json!("busbar_response_format")),
        "{v}"
    );
    assert!(
        !r.dropped_controls.iter().any(|c| c == "response_format"),
        "{:?}",
        r.dropped_controls
    );
}

/// `tool_choice: none` crossing to bedrock still goes out, and is reported dropped
/// (`tool_choice=none`), which the door records as a degraded audit row.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/egress_dropped_controls_audit_tests.rs::openai_to_bedrock_tool_choice_none_forwards_and_audits_degraded`.
#[test]
fn a_tool_choice_none_crossing_to_bedrock_goes_out_and_is_reported_dropped() {
    let r = far(
        OPENAI,
        &chat(json!({
            "tools": [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}],
            "tool_choice": "none"
        })),
        "m-bedrock",
    );
    assert!(!r.body.is_empty());
    assert!(
        r.dropped_controls.iter().any(|c| c == "tool_choice=none"),
        "{:?}",
        r.dropped_controls
    );
}

/// The controls each far dialect reports dropped for one request: anthropic none of them, bedrock
/// `response_format` then `tool_choice=none`, openai (the caller's own dialect) nothing at all, and
/// an anthropic lane declaring native structured outputs the schema-less `response_format`.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/egress_dropped_controls_audit_tests.rs::egress_dropped_controls_reports_the_right_controls_per_dialect`.
#[test]
fn each_far_dialect_reports_the_controls_it_drops() {
    let body = chat(json!({
        "tools": [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}],
        "response_format": {"type": "json_object"},
        "tool_choice": "none"
    }));
    let controls = ["response_format", "tool_choice=none"];
    let named = |r: &FarRequest| -> Vec<String> {
        r.dropped_controls
            .iter()
            .filter(|c| controls.contains(&c.as_str()))
            .cloned()
            .collect()
    };
    assert_eq!(
        named(&far(OPENAI, &body, "m-anthropic")),
        Vec::<String>::new()
    );
    let bedrock = far(OPENAI, &body, "m-bedrock");
    assert_eq!(
        bedrock.dropped_controls.get(..2),
        Some(
            &[
                "response_format".to_string(),
                "tool_choice=none".to_string()
            ][..]
        ),
        "the controls first: {:?}",
        bedrock.dropped_controls
    );
    assert!(far(OPENAI, &body, "m-openai").dropped_controls.is_empty());
    assert_eq!(
        named(&far(OPENAI, &body, "claude-opus-5")),
        ["response_format"],
    );
}

/// A lane declaring native structured outputs carries a schema on `output_config.format` (no forced
/// tool), and drops a schema-less `json_object`, reporting it.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/egress_dropped_controls_audit_tests.rs::native_structured_output_lane_drops_schema_less_json_with_audit`.
#[test]
fn a_native_structured_output_lane_rides_a_schema_and_drops_a_schema_less_json_mode() {
    let schema = json!({"type": "object", "properties": {"a": {"type": "string"}}});
    let r = far(
        OPENAI,
        &chat(
            json!({"response_format": {"type": "json_schema", "json_schema": {"name": "o", "schema": schema}}}),
        ),
        "claude-opus-5",
    );
    let v = sent(&r);
    assert_eq!(
        v.pointer("/output_config/format/type"),
        Some(&json!("json_schema")),
        "{v}"
    );
    assert!(v.get("tool_choice").is_none(), "{v}");

    let r = far(
        OPENAI,
        &chat(json!({"response_format": {"type": "json_object"}})),
        "claude-opus-5",
    );
    let v = sent(&r);
    assert!(v.get("output_config").is_none(), "{v}");
    assert!(v.get("tools").is_none(), "{v}");
    assert!(
        r.dropped_controls.iter().any(|c| c == "response_format"),
        "{:?}",
        r.dropped_controls
    );
}

// ── the per-far-end reshapes and the router keys ────────────────────────────────────────────────

/// An anthropic lane on a Vertex path base drops the body `model` (it rides the URL) and carries
/// Vertex's `anthropic_version` discriminator, keeping the rest of the request.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/request_short_circuit_tests.rs::claude_on_vertex_drops_model_and_injects_anthropic_version`.
#[test]
fn claude_on_vertex_drops_the_model_and_carries_the_vertex_version() {
    let body = json!({"model": "claude-3-5-sonnet", "max_tokens": 7,
        "messages": [{"role": "user", "content": "hi"}]});
    for (target, b) in [
        ("/v1/messages", body.clone()),
        (OPENAI, chat(json!({"max_tokens": 7}))),
    ] {
        let r = far(target, &b, "claude-3-5-sonnet");
        let v = sent(&r);
        assert!(v.get("model").is_none(), "{target}: {v}");
        assert_eq!(
            v.get("anthropic_version").and_then(Value::as_str),
            Some("vertex-2023-10-16"),
            "{target}: {v}"
        );
        assert!(v.get("messages").is_some(), "{target}: {v}");
    }
}

/// The array-stream router key one dialect declares.
fn shim_key() -> &'static str {
    busbar_plane_llm::codec::DECLS
        .iter()
        .find_map(|d| d.array_stream_shim_key)
        .expect("a dialect declares an array-stream router key")
}

fn far_shape(dialect: &'static str, wire_model: &'static str) -> FarShape<'static> {
    FarShape {
        dialect,
        wire_model,
        default_max_tokens: None,
        prompt_caching: false,
        caps: Default::default(),
        path_base: None,
    }
}

/// The array-stream router key is stripped from every far end, so a body carrying it is never sent
/// as the caller's bytes.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/request_short_circuit_tests.rs::invalidator_1_gemini_array_shim_key_forces_non_pristine`.
#[test]
fn the_array_stream_router_key_is_stripped_and_the_body_is_no_longer_the_callers() {
    let body = serde_json::to_vec(&json!({"model": "gpt-4o", "messages": [], (shim_key()): true}))
        .expect("serializes");
    let out = relay_request(far_shape("openai", "gpt-4o"), "application/json", &body);
    assert!(!out.pristine);
    assert_ne!(out.bytes.as_ref(), body.as_slice());
    let v: Value = serde_json::from_slice(&out.bytes).expect("JSON");
    assert!(v.get(shim_key()).is_none(), "{v}");
}

/// `stream` on a far end whose model and stream ride the URL is stripped.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/request_short_circuit_tests.rs::invalidator_2_stream_on_path_model_egress_forces_non_pristine`.
#[test]
fn stream_is_stripped_for_a_far_end_whose_url_carries_it() {
    let body = serde_json::to_vec(
        &json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}], "stream": true}),
    )
    .expect("serializes");
    let out = relay_request(
        far_shape("gemini", "url-model-x"),
        "application/json",
        &body,
    );
    assert!(!out.pristine);
    assert_ne!(out.bytes.as_ref(), body.as_slice());
    let v: Value = serde_json::from_slice(&out.bytes).expect("JSON");
    assert!(v.get("stream").is_none(), "{v}");
}

/// `stream` on a far end that reads it from the body is kept, and a body already naming the lane's
/// model goes out byte for byte.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/request_short_circuit_tests.rs::invalidator_2_stream_on_body_model_egress_stays_pristine`.
#[test]
fn stream_is_kept_for_a_far_end_that_reads_it_from_the_body() {
    let body = serde_json::to_vec(&json!({"model": "gpt-4o", "messages": [], "stream": true}))
        .expect("serializes");
    let out = relay_request(far_shape("openai", "gpt-4o"), "application/json", &body);
    assert!(out.pristine);
    assert_eq!(out.bytes.as_ref(), body.as_slice());
}

/// A same-dialect body carrying a `model` for a far end whose URL names the model has it stripped.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/request_short_circuit_tests.rs::invalidator_4_same_proto_model_shim_strip_forces_non_pristine`.
#[test]
fn a_body_model_is_stripped_for_a_far_end_whose_url_names_the_model() {
    let body = serde_json::to_vec(
        &json!({"model": "router-shim", "contents": [{"role": "user", "parts": [{"text": "hi"}]}]}),
    )
    .expect("serializes");
    let out = relay_request(
        far_shape("gemini", "url-model-x"),
        "application/json",
        &body,
    );
    assert!(!out.pristine);
    assert_ne!(out.bytes.as_ref(), body.as_slice());
    let v: Value = serde_json::from_slice(&out.bytes).expect("JSON");
    assert!(v.get("model").is_none(), "{v}");
}

/// The translated body's strip: the array-stream key for every far end, `stream` for a far end whose
/// URL carries it, and never `model`.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_strip_router_shim_keys`.
#[test]
fn the_router_key_strip_removes_the_array_key_everywhere_and_stream_only_where_the_url_carries_it()
{
    use busbar_plane_llm::codec::wire_shim::strip_router_shim_keys;
    let mut v = json!({"model": "p", "stream": true, (shim_key()): true, "messages": []});
    strip_router_shim_keys(&mut v, "bedrock");
    assert_eq!(v["model"], "p", "model is never stripped here");
    assert!(v.get("stream").is_none());
    assert!(v.get(shim_key()).is_none());
    assert!(v.get("messages").is_some());

    let mut v = json!({"stream": true, (shim_key()): true});
    strip_router_shim_keys(&mut v, "gemini");
    assert!(v.get("stream").is_none() && v.get(shim_key()).is_none());

    let mut v = json!({"model": "gpt-4o", "stream": true, (shim_key()): true});
    strip_router_shim_keys(&mut v, "openai");
    assert_eq!(v["model"], "gpt-4o");
    assert_eq!(v["stream"], true);
    assert!(v.get(shim_key()).is_none());
}

/// A URL-model caller crossing to a body-model far end reaches it with the lane's model and its
/// `stream`, and no router key; within one URL-model dialect the relay sends the caller's own bytes,
/// no `model` or `stream` the arrival carried for routing.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_shim_strip_ordering_cross_protocol_keeps_model`.
#[test]
fn a_crossing_keeps_the_lanes_model_and_a_same_dialect_relay_sends_the_callers_bytes() {
    use busbar_plane_llm::codec::wire_shim::strip_router_shim_keys;
    let mut v = json!({"model": "router-placeholder", "stream": true, (shim_key()): true});
    strip_router_shim_keys(&mut v, "openai");
    busbar_plane_llm::codec::decl_of("openai")
        .and_then(|d| d.dialect())
        .expect("openai codec")
        .rewrite_model_if_needed(&mut v, "gpt-4o");
    assert_eq!(v["model"], "gpt-4o");
    assert_eq!(v["stream"], true);
    assert!(v.get(shim_key()).is_none());

    // The same through the attempt: a streamed array caller of the URL-model dialect, to openai.
    let a = arrive(
        "POST",
        "/v1beta/models/router-placeholder:streamGenerateContent",
        &json_head(),
        br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#,
        &(),
    )
    .expect("arrives");
    let r = build(&a, &json_head(), &shaping(), "p", "m-openai").expect("built");
    let v = sent(&r);
    assert_eq!(v["model"], "m-openai", "{v}");
    assert_eq!(v["stream"], true, "{v}");
    assert!(v.get(shim_key()).is_none(), "{v}");

    let caller = br#"{ "contents": [ ], "z" : 1.0 }"#;
    let carried = br#"{"model":"router-placeholder","stream":true, "contents": [ ], "z" : 1.0 }"#;
    let relayed = relay_request(
        far_shape("gemini", "gemini-1.5-pro"),
        "application/json",
        carried,
    );
    assert_eq!(relayed.bytes.as_ref(), caller.as_slice());
}

// ── the usage opt-in splice ─────────────────────────────────────────────────────────────────────

fn ask(body: &[u8]) -> Vec<u8> {
    try_inject_stream_include_usage(body.to_vec()).expect("asked")
}

fn stream_options_keys(out: &[u8]) -> usize {
    out.windows(br#""stream_options""#.len())
        .filter(|w| *w == br#""stream_options""#)
        .count()
}

/// A body already carrying `stream_options` gains no second one: its `include_usage` is set true
/// where it stands.
///
/// Ports legacy `crates/busbar-llm/src/engine/engine_tests/inject_include_usage_tests.rs::injector_idempotent_when_stream_options_already_present`.
#[test]
fn the_usage_ask_never_duplicates_stream_options() {
    let out = ask(
        br#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false},"messages":[]}"#,
    );
    let v: Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&json!(true)),
        "{v}"
    );
    assert_eq!(
        stream_options_keys(&out),
        1,
        "{}",
        String::from_utf8_lossy(&out)
    );
}

/// `{}` gains the member; a non-object body passes unchanged.
///
/// Ports legacy `crates/busbar-llm/src/engine/engine_tests/inject_include_usage_tests.rs::injector_falls_back_on_empty_or_non_object`.
#[test]
fn the_usage_ask_fills_an_empty_object_and_passes_a_non_object() {
    let v: Value = busbar_plane_llm::codec::json::parse(&ask(b"{}")).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&json!(true)),
        "{v}"
    );
    assert_eq!(ask(b"[1,2,3]"), b"[1,2,3]");
}

/// An all-whitespace body passes through untouched, without reading past its end.
///
/// Ports legacy `crates/busbar-llm/src/engine/engine_tests/inject_include_usage_tests.rs::injector_does_not_overrun_an_all_whitespace_body`.
#[test]
fn the_usage_ask_passes_an_all_whitespace_body() {
    assert_eq!(ask(b"   \n\t "), b"   \n\t ");
}

/// An existing `stream_options` keeps its siblings when its flag is set.
///
/// Ports legacy `crates/busbar-llm/src/engine/engine_tests/inject_include_usage_tests.rs::upgrades_existing_stream_options_preserving_siblings`.
#[test]
fn the_usage_ask_keeps_the_siblings_of_stream_options() {
    let out = ask(
        br#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false,"foo":1},"messages":[]}"#,
    );
    let v: Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&json!(true)),
        "{v}"
    );
    assert_eq!(v.pointer("/stream_options/foo"), Some(&json!(1)), "{v}");
}

/// A body already opted in stays opted in.
///
/// Ports legacy `crates/busbar-llm/src/engine/engine_tests/inject_include_usage_tests.rs::keeps_existing_true`.
#[test]
fn the_usage_ask_keeps_an_existing_true() {
    let out = ask(br#"{"stream":true,"stream_options":{"include_usage":true}}"#);
    let v: Value = busbar_plane_llm::codec::json::parse(&out).expect("valid JSON");
    assert_eq!(
        v.pointer("/stream_options/include_usage"),
        Some(&json!(true))
    );
}

/// A caller's `stream_options` is edited in place, byte for byte: the flag set where it stands, set
/// first in an object that lacks it, and a `null` replaced.
///
/// Ports legacy `crates/busbar-llm/src/engine/engine_tests/inject_include_usage_tests.rs::an_existing_stream_options_is_edited_in_place`.
#[test]
fn the_usage_ask_edits_an_existing_stream_options_in_place() {
    assert_eq!(
        ask(br#"{"model":"gpt-4o", "stream":true,"stream_options":{"foo":1, "include_usage":false},"messages":[]}"#),
        br#"{"model":"gpt-4o", "stream":true,"stream_options":{"foo":1, "include_usage":true},"messages":[]}"#
    );
    assert_eq!(
        ask(br#"{"stream":true,"stream_options":{ "foo":1 },"z":1}"#),
        br#"{"stream":true,"stream_options":{"include_usage":true, "foo":1 },"z":1}"#
    );
    assert_eq!(
        ask(br#"{"stream":true,"stream_options":null,"z":1}"#),
        br#"{"stream":true,"stream_options":{"include_usage":true},"z":1}"#
    );
}

// ── the multi-candidate and stop-list degrades ──────────────────────────────────────────────────

/// An openai `n: 3` crossing to anthropic goes out (one candidate, `n` not crossing), never refused.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/multi_candidate_degrade_tests.rs::openai_to_anthropic_n_gt_1_is_forwarded_not_rejected`.
#[test]
fn a_multi_candidate_ask_crossing_to_anthropic_goes_out() {
    let r = far(
        OPENAI,
        &chat(json!({"max_tokens": 16, "n": 3})),
        "m-anthropic",
    );
    let v = sent(&r);
    assert!(v.get("n").is_none(), "{v}");
    assert!(v.get("messages").is_some(), "{v}");
}

/// A gemini `candidateCount: 2` crossing to openai goes out, never refused.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/multi_candidate_degrade_tests.rs::gemini_ingress_to_openai_candidate_count_gt_1_is_forwarded_not_rejected`.
#[test]
fn a_candidate_count_crossing_to_openai_goes_out() {
    let r = far(
        "/v1beta/models/gpt-4o:generateContent",
        &json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                "generationConfig": {"candidateCount": 2}}),
        "m-openai",
    );
    assert!(sent(&r).get("messages").is_some(), "{}", sent(&r));
}

/// A same-dialect `n: 3` is relayed unchanged.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/multi_candidate_degrade_tests.rs::openai_to_openai_n_gt_1_is_preserved_verbatim`.
#[test]
fn a_same_dialect_multi_candidate_ask_is_relayed_unchanged() {
    let r = far(
        OPENAI,
        &chat(json!({"model": "m-openai", "n": 3})),
        "m-openai",
    );
    assert!(r.pristine);
    assert_eq!(sent(&r).get("n"), Some(&json!(3)));
}

/// A single-candidate crossing (`n: 1`, or none) goes out.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/multi_candidate_degrade_tests.rs::single_candidate_cross_protocol_is_not_rejected`.
#[test]
fn a_single_candidate_crossing_goes_out() {
    for extra in [json!({"max_tokens": 16, "n": 1}), json!({"max_tokens": 16})] {
        let a = arrived(OPENAI, &chat(extra.clone()));
        assert!(
            build(&a, &json_head(), &shaping(), "p", "m-anthropic").is_ok(),
            "{extra}"
        );
    }
}

/// Multi-input embeddings to a far end that embeds one input go out with the FIRST input.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/multi_candidate_degrade_tests.rs::multi_input_embeddings_to_gemini_embeds_first_not_rejected`.
#[test]
fn multi_input_embeddings_to_a_single_input_far_end_embed_the_first() {
    let r = far(
        "/v1/embeddings",
        &json!({"model": "text-embedding-3-small", "input": ["alpha", "beta", "gamma"]}),
        "text-embedding-004",
    );
    assert_eq!(
        sent(&r).pointer("/content/parts/0/text"),
        Some(&json!("alpha")),
        "{}",
        sent(&r)
    );
}

/// Single-input embeddings to that far end go out.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/multi_candidate_degrade_tests.rs::single_input_embeddings_to_gemini_is_allowed`.
#[test]
fn single_input_embeddings_to_a_single_input_far_end_go_out() {
    let a = arrived(
        "/v1/embeddings",
        &json!({"model": "text-embedding-3-small", "input": ["alpha"]}),
    );
    assert!(build(&a, &json_head(), &shaping(), "p", "text-embedding-004").is_ok());
}

/// A stop list over the far end's cap is clamped to the cap and goes out.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/stop_sequence_cap_degrade_tests.rs::openai_to_cohere_over_cap_stop_sequences_is_clamped_not_rejected`.
#[test]
fn an_over_cap_stop_list_is_clamped_to_the_far_ends_cap() {
    let r = far(
        OPENAI,
        &chat(json!({"stop": ["a", "b", "c", "d", "e", "f"]})),
        "m-cohere",
    );
    assert_eq!(
        sent(&r).get("stop_sequences"),
        Some(&json!(["a", "b", "c", "d", "e"])),
        "{}",
        sent(&r)
    );
}

/// A stop list exactly at the cap goes out whole.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/stop_sequence_cap_degrade_tests.rs::openai_to_cohere_exactly_cap_stop_sequences_is_allowed`.
#[test]
fn an_at_cap_stop_list_goes_out_whole() {
    let r = far(
        OPENAI,
        &chat(json!({"stop": ["a", "b", "c", "d", "e"]})),
        "m-cohere",
    );
    assert_eq!(
        sent(&r).get("stop_sequences"),
        Some(&json!(["a", "b", "c", "d", "e"])),
        "{}",
        sent(&r)
    );
}

// ── a huge body ─────────────────────────────────────────────────────────────────────────────────

/// A request well over 128 KiB is written for a far end like a small one: relayed byte for byte
/// within one dialect, and translated across.
///
/// Ports the request half of legacy `crates/busbar-llm/src/engine/tests/translate_offload_tests.rs::huge_body_translates_via_offload_and_forwards`
/// (the served half is `serve_door_exchange_ported::a_huge_request_is_served_like_a_small_one`).
#[test]
fn a_huge_request_is_written_like_a_small_one() {
    let big = "x".repeat(300 * 1024);
    let body = json!({"model": "m-openai", "messages": [{"role": "user", "content": big}],
        "max_tokens": 16});
    let bytes = serde_json::to_vec(&body).expect("serializes");
    assert!(bytes.len() >= 128 * 1024);
    let same = far(OPENAI, &body, "m-openai");
    assert!(same.pristine);
    assert_eq!(same.body, bytes);
    let crossed = far(OPENAI, &body, "m-anthropic");
    let v = sent(&crossed);
    let content = &v["messages"][0]["content"];
    let text = content
        .as_str()
        .or_else(|| content.pointer("/0/text").and_then(Value::as_str));
    assert_eq!(text, Some(big.as_str()), "the whole content crosses");
}

// ── the chat operation's declared capabilities ──────────────────────────────────────────────────

/// The chat operation streams, taps its single answer's usage, reads the caller's stream intent off
/// the `stream` boolean, and keys session affinity off a non-empty `system`.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/dialect_registry_facts_tests.rs::chat_declares_its_capabilities`.
#[test]
fn the_chat_operation_declares_its_capabilities() {
    let a = arrived(OPENAI, &chat(json!({})));
    assert_eq!(a.operation.name(), "chat");
    let chat_op = busbar_plane_llm::exchange::handler_of(&a).expect("openai serves chat");
    assert!(chat_op.streaming(), "chat streams");
    assert!(chat_op.taps_usage(), "chat bills tokens from the body");
    assert!(chat_op.wants_stream(&json!({"stream": true})));
    assert!(!chat_op.wants_stream(&json!({})));
    assert_eq!(
        chat_op.body_affinity_key(&json!({"system": "you are helpful"})),
        Some("you are helpful")
    );
    assert_eq!(chat_op.body_affinity_key(&json!({"system": ""})), None);
}
