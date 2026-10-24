// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `arrive`: the dialect, operation and model an arrival names, and the previous release's refusals.

use busbar_plane_llm::exchange::arrive::*;
use serde_json::Value;

fn head(pairs: &[(&'static str, &'static str)]) -> Vec<(&'static [u8], &'static [u8])> {
    pairs
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect()
}

fn json() -> Vec<(&'static [u8], &'static [u8])> {
    head(&[("content-type", "application/json")])
}

fn ok(target: &str, h: &[(&[u8], &[u8])], body: &[u8]) -> Arrived {
    arrive("POST", target, h, body, &()).unwrap_or_else(|d| panic!("{target}: refused {d:?}"))
}

fn no(target: &str, h: &[(&[u8], &[u8])], body: &[u8]) -> Declined {
    match arrive("POST", target, h, body, &()) {
        Ok(a) => panic!("{target}: served as {} {}", a.dialect, a.model),
        Err(d) => d,
    }
}

#[test]
fn a_body_model_dialect_reads_its_model_off_the_body() {
    let a = ok(
        "/v1/chat/completions",
        &json(),
        br#"{"model":"gpt-4o","messages":[]}"#,
    );
    assert_eq!((a.dialect, a.model.as_str()), ("openai", "gpt-4o"));
    assert!(a.path_model.is_none());
    let a = ok(
        "/v1/messages",
        &head(&[
            ("content-type", "application/json"),
            ("anthropic-version", "2023-06-01"),
        ]),
        br#"{"model":"claude","max_tokens":1,"messages":[]}"#,
    );
    assert_eq!((a.dialect, a.model.as_str()), ("anthropic", "claude"));
}

#[test]
fn a_path_nobody_claims_is_the_routers_not_found() {
    let d = no("/nowhere", &json(), b"{}");
    assert_eq!(d.why, Decline::NoResource);
    assert_eq!(d.status, 404);
    assert_eq!(d.kind, "not_found_error");
    assert_eq!(d.message, "the requested resource was not found");
}

#[test]
fn an_unparseable_body_and_a_missing_model_are_the_released_400s() {
    let d = no("/v1/chat/completions", &json(), b"{not json");
    assert_eq!((d.why, d.status), (Decline::BodyParse, 400));
    assert_eq!(
        d.message,
        "We could not parse the JSON body of your request."
    );
    assert_eq!(d.envelope, "openai");
    let d = no("/v1/chat/completions", &json(), br#"{"messages":[]}"#);
    assert_eq!((d.why, d.status), (Decline::MissingModel, 400));
    assert_eq!(d.message, "Missing required parameter: 'model'.");
    let d = no("/v1/chat/completions", &json(), br#"{"model":""}"#);
    assert_eq!(d.why, Decline::MissingModel, "an empty model is no model");
}

#[test]
fn a_multipart_arrival_reads_the_model_part() {
    let h = head(&[("content-type", "multipart/form-data; boundary=zz")]);
    let body =
        b"--zz\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--zz--\r\n";
    let a = ok("/v1/audio/transcriptions", &h, body);
    assert_eq!(a.model, "whisper-1");
    assert!(a.parsed.is_none());
}

#[test]
fn the_named_surface_takes_its_model_from_the_path() {
    let a = ok(
        "/my-pool/v1/messages",
        &json(),
        br#"{"max_tokens":1,"messages":[]}"#,
    );
    assert_eq!((a.dialect, a.model.as_str()), ("anthropic", "my-pool"));
    let a = ok(
        "/prov/some%2Fmodel/v1/messages",
        &json(),
        br#"{"messages":[]}"#,
    );
    assert_eq!(a.model, "some/model");
}

struct One;
impl Catalogue for One {
    fn provider_of(&self, model: &str) -> Option<&str> {
        (model == "m").then_some("right")
    }
}

#[test]
fn the_adhoc_surface_refuses_a_model_another_provider_serves() {
    let d = arrive("POST", "/wrong/m/v1/messages", &json(), b"{}", &One).expect_err("refused");
    assert_eq!((d.why, d.status), (Decline::ProviderMismatch, 400));
    // Q128 u58: the refusal names the entry it concerns, so the kernel holds it behind the
    // caller's identity and grant (1.5.5 ran the ad-hoc route's governance guard first).
    assert_eq!(d.entry.as_deref(), Some("m"));
    assert_eq!(
        d.message,
        "The model 'm' does not exist or you do not have access to it."
    );
    assert!(arrive("POST", "/right/m/v1/messages", &json(), b"{}", &One).is_ok());
}

#[test]
fn gemini_names_its_model_and_stream_in_the_url() {
    let a = ok(
        "/v1beta/models/gemini-pro:streamGenerateContent",
        &json(),
        br#"{"contents":[]}"#,
    );
    assert_eq!((a.dialect, a.model.as_str()), ("gemini", "gemini-pro"));
    let pm = a.path_model.expect("a path model");
    assert!(pm.stream && pm.json_array);
    let v: Value = busbar_plane_llm::codec::json::parse(&a.body).expect("spliced JSON");
    assert_eq!(v["model"], "gemini-pro");
    assert_eq!(v["stream"], true);
    let (key, value) = busbar_plane_llm::codec::gemini::STREAM_QUERY;
    let a = ok(
        &format!("/v1beta/models/gemini-pro:streamGenerateContent?{key}={value}"),
        &json(),
        br#"{"contents":[]}"#,
    );
    assert!(!a.path_model.expect("a path model").json_array);
}

#[test]
fn gemini_refuses_a_non_object_body_and_an_unknown_action() {
    let d = no("/v1beta/models/gemini-pro:generateContent", &json(), b"[1]");
    assert_eq!((d.why, d.status), (Decline::NotAnObject, 400));
    assert_eq!(d.message, "Request body must be a JSON object.");
    let d = no("/v1beta/models/gemini-pro:fly", &json(), b"{}");
    assert_eq!((d.why, d.status), (Decline::PathNotFound, 404));
}

#[test]
fn bedrock_names_its_model_in_the_url() {
    let a = ok(
        "/model/anthropic.claude-v2/converse",
        &json(),
        br#"{"messages":[]}"#,
    );
    assert_eq!(
        (a.dialect, a.model.as_str()),
        ("bedrock", "anthropic.claude-v2")
    );
    assert!(!a.path_model.expect("a path model").stream);
    let a = ok(
        "/model/anthropic.claude-v2/converse-stream",
        &json(),
        br#"{"messages":[]}"#,
    );
    assert!(a.path_model.expect("a path model").stream);
}

#[test]
fn every_decline_code_is_nonzero_and_distinct() {
    let all = [
        Decline::NoResource,
        Decline::UnsupportedOperation,
        Decline::BodyParse,
        Decline::NotAnObject,
        Decline::Reserialize,
        Decline::MissingModel,
        Decline::PathNotFound,
        Decline::InvokeBody,
        Decline::ProviderMismatch,
        Decline::MethodNotAllowed,
    ];
    for (i, d) in all.iter().enumerate() {
        assert_ne!(d.code(), 0);
        assert!(all[..i].iter().all(|e| e.code() != d.code()));
    }
}

#[test]
fn a_dialect_path_takes_post_only_and_an_unknown_path_is_not_found_first() {
    for target in ["/v1/chat/completions", "/my-pool/v1/messages"] {
        let d = arrive("GET", target, &json(), b"", &()).expect_err("refused");
        assert_eq!(
            (d.why, d.status),
            (Decline::MethodNotAllowed, 405),
            "{target}"
        );
        assert_eq!(d.message, "method not allowed for this resource");
        assert_eq!(d.kind, "invalid_request_error");
    }
    let d = arrive("GET", "/nowhere", &json(), b"", &()).expect_err("refused");
    assert_eq!(
        d.why,
        Decline::NoResource,
        "no dialect: the 404 comes first"
    );
}

// ── rehomed from the legacy engine's arrival, decode and ingress tests ──────────────────────────

use busbar_contract::codec::OperationHandler;
use busbar_contract::operation::OpVerb;
use busbar_plane_llm::exchange::attempt::build;
use busbar_plane_llm::exchange::refuse::{declined, kernel_refusal, model_not_found, render};
use busbar_plane_llm::exchange::reply::whole::{self, WholeCtx, WholeEnd};
use busbar_plane_llm::exchange::shaping::Shaping;
use busbar_plane_llm::refusal::reason;
use serde_json::json;

/// The host the exchange is handed: a fixed entropy byte, so a dialect that mints a request id
/// mints one (the same one every time), and no clock.
struct FixedHost;

impl busbar_contract::codec::CodecHost for FixedHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        out.fill(7);
        true
    }

    fn wall_clock_now(&self) -> Option<u64> {
        None
    }
}

const HOST: &dyn busbar_contract::codec::CodecHost = &FixedHost;

fn body_json(bytes: &[u8]) -> Value {
    busbar_plane_llm::codec::json::parse(bytes).expect("JSON")
}

/// The caller's rendered refusal for a declined arrival, as JSON.
fn rendered(d: &Declined) -> (u16, Vec<String>, Value) {
    let r = declined(HOST, d);
    let names = r.fields.iter().map(|(n, _)| n.clone()).collect();
    (r.status, names, body_json(&r.body))
}

/// One openai far end `member` (pool `p`), for the routes that reach a far end.
fn openai_lane(member: &str) -> Shaping {
    let mut models = serde_json::Map::new();
    models.insert(member.to_string(), json!({ "provider": "far" }));
    Shaping::from_settings(&json!({
        "providers": { "far": { "protocol": "openai", "base_url": "https://far.example" } },
        "models": Value::Object(models),
        "pools": { "p": { "members": [member] } }
    }))
    .expect("reads")
}

fn openai_ok_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "model": "foo",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi there"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3}
    }))
    .expect("JSON")
}

fn gemini_from_openai<'a>(a: &'a Arrived, model: &'a str, json_array: bool) -> WholeCtx<'a> {
    WholeCtx {
        ingress: "gemini",
        egress: "openai",
        operation: a.operation,
        model,
        wants_stream: a.path_model.as_ref().is_some_and(|p| p.stream),
        json_array,
        request: a.parsed.as_ref(),
        now_s: 1_752_000_000,
        elapsed_ms: Some(12),
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
    }
}

/// Rehomes `crates/busbar-llm/src/engine/tests/auth_native_envelope_tests.rs::test_residual_dialect_inference`.
/// 1.5.5 behaviour pinned: the dialect a refusal on a path is shaped in, from the path's shape
/// alone, for every legacy path: gemini on `/v1beta/models/...` (with or without an action) and on
/// `/v1/models/...:<action>`; openai on a colon-less `/v1/models/{id}`, a `/model/...` path with no
/// converse suffix and an unknown path; bedrock on `/model/.../converse[-stream]`; anthropic on
/// any `.../v1/messages`, a model literally named `model` included; cohere and responses on theirs.
/// RED if any path is shaped in another dialect.
#[test]
fn every_paths_refusal_envelope_is_read_off_its_shape() {
    for (path, dialect) in [
        ("/v1beta/models/gemini-1.5:generateContent", "gemini"),
        ("/v1/models/gemini-pro:generateContent", "gemini"),
        ("/v1/models/gemini-1.5-pro:streamGenerateContent", "gemini"),
        ("/v1/models/gpt-4o", "openai"),
        ("/v1beta/models/gemini-pro", "gemini"),
        ("/model/anthropic.claude/converse", "bedrock"),
        ("/model/anthropic.claude/converse-stream", "bedrock"),
        ("/model/v1/messages", "anthropic"),
        ("/model/foo/bar", "openai"),
        ("/v1/messages", "anthropic"),
        ("/pa/v1/messages", "anthropic"),
        ("/anthropic/claude/v1/messages", "anthropic"),
        ("/v1/chat/completions", "openai"),
        ("/v2/chat", "cohere"),
        ("/v1/responses", "responses"),
        ("/stats", "openai"),
    ] {
        assert_eq!(envelope_for(path), dialect, "{path}");
    }
}

/// Rehomes `crates/busbar-llm/src/engine/tests/auth_native_envelope_tests.rs::test_every_router_ingress_path_maps_to_non_fallback_proto`.
/// 1.5.5 behaviour pinned: every ingress path family the router serves names its own dialect by
/// shape, never the unknown-path fallback, and that dialect is one the plane holds: anthropic
/// (plain and named), openai, cohere, responses, gemini (v1beta and the stable v1 alias) and
/// bedrock (converse and converse-stream). RED if any falls to the fallback or names an unknown
/// dialect.
#[test]
fn every_served_ingress_path_names_its_own_dialect() {
    for (path, dialect) in [
        ("/v1/messages", "anthropic"),
        ("/somepool/v1/messages", "anthropic"),
        ("/v1/chat/completions", "openai"),
        ("/v2/chat", "cohere"),
        ("/v1/responses", "responses"),
        ("/v1beta/models/gemini-1.5:generateContent", "gemini"),
        ("/v1/models/gemini-pro:generateContent", "gemini"),
        ("/model/anthropic.claude/converse", "bedrock"),
        ("/model/anthropic.claude/converse-stream", "bedrock"),
    ] {
        assert_eq!(residual(path), Some(dialect), "{path}: not the fallback");
        assert!(
            busbar_plane_llm::codec::DECLS
                .iter()
                .any(|d| d.name == dialect),
            "{path}: {dialect} is a dialect the plane holds"
        );
    }
}

/// Rehomes `crates/busbar-llm/src/engine/tests/auth_native_envelope_tests.rs::the_residual_dialect_table_shapes_fallback_errors`.
/// 1.5.5 behaviour pinned: the table the fallback 404/405/413 are shaped by: openai, responses and
/// cohere on theirs; gemini on both surfaces (with an action on v1, always on v1beta); openai on
/// `GET /v1/models/{id}`, on the list-models `/v1/models`, on a non-converse `/model/...` (no
/// bedrock shape) and on an unknown path; anthropic on a named surface.
/// RED if any row is shaped in another dialect.
#[test]
fn the_fallback_refusals_shape_table_is_the_released_one() {
    for (path, dialect) in [
        ("/v1/chat/completions", "openai"),
        ("/v1/responses", "responses"),
        ("/v2/chat", "cohere"),
        ("/v1/models/gemini-pro:generateContent", "gemini"),
        ("/v1beta/models/gemini-pro:streamGenerateContent", "gemini"),
        ("/v1/models/gpt-4o", "openai"),
        ("/v1/models", "openai"),
        ("/v1/models/gemini-1.5-pro:generateContent", "gemini"),
        ("/v1beta/models/gemini-pro", "gemini"),
        ("/model/anthropic.claude/converse", "bedrock"),
        ("/model/anthropic.claude/converse-stream", "bedrock"),
        ("/my-model/v1/messages", "anthropic"),
        ("/model/foo/bar", "openai"),
        ("/model/foo/predict", "openai"),
        ("/totally/unknown", "openai"),
    ] {
        assert_eq!(envelope_for(path), dialect, "{path}");
    }
    for path in ["/model/foo/bar", "/model/foo/predict", "/totally/unknown"] {
        assert_ne!(residual(path), Some("bedrock"), "{path}");
    }
}

/// Rehomes `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_adhoc_rejects_unconfigured_provider_model`.
/// 1.5.5 behaviour pinned: the ad-hoc `/{provider}/{model}/v1/messages` route reaches configured
/// models only: an attacker's `evil.example.com` / `../secret` names no configured model, so the
/// answer is the not-found 404 (this plane states 404 for a model with no destination) and no far
/// end is reached; a configured model on the wrong provider is refused 400 at the door.
/// RED if the unknown model reaches a far end or reads another status, or the mismatch is not 400.
#[test]
fn the_adhoc_route_reaches_configured_models_only() {
    let catalogue = Shaping::from_settings(&json!({
        "providers": { "openai": { "protocol": "openai", "base_url": "https://configured.example.com" } },
        "models": { "test-model": { "provider": "openai" } }
    }))
    .expect("reads");
    let a = arrive(
        "POST",
        "/evil.example.com/..%2Fsecret/v1/messages",
        &json(),
        br#"{"messages":[]}"#,
        &catalogue,
    )
    .expect("the door takes the route as asked");
    assert_eq!(a.model, "../secret");
    assert!(catalogue.lane("../secret").is_none(), "no far end to reach");
    // The no-destination status is the kernel's class default (`NotFound`, 404), not a row.
    assert!(!busbar_plane_llm::refusal::REFUSAL_STATUSES
        .iter()
        .any(|r| r.reason == reason::NO_DESTINATION));
    assert_eq!(
        busbar_contract::abi::plane::reason_of(reason::NO_DESTINATION)
            .map(busbar_contract::abi::plane::class_of),
        Some(busbar_contract::abi::plane::RefusalClass::NotFound)
    );
    let r = kernel_refusal(
        HOST,
        a.dialect,
        reason::NO_DESTINATION,
        404,
        &model_not_found(&a.model, None),
        0,
    );
    assert_eq!(r.status, 404);

    let d = arrive(
        "POST",
        "/wrong-provider/test-model/v1/messages",
        &json(),
        br#"{"messages":[]}"#,
        &catalogue,
    )
    .expect_err("refused at the door");
    assert_eq!((d.why, d.status), (Decline::ProviderMismatch, 400));
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_path_resolves_model_and_stream`.
/// 1.5.5 behaviour pinned: a buffered gemini `/v1beta/models/foo:generateContent` names model
/// `foo` and no stream; routed to an openai far end the far body carries `messages` and no
/// `stream: true`, and the caller's answer is gemini's own (`candidates`, never `choices`) at 200.
/// RED if the model or stream reads otherwise, the far body is not OpenAI-shaped, or the caller's
/// body carries `choices`.
#[test]
fn a_buffered_gemini_arrival_routes_by_its_url_model_and_reads_gemini_back() {
    let body = r#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#;
    let a = ok(
        "/v1beta/models/foo:generateContent",
        &json(),
        body.as_bytes(),
    );
    assert_eq!((a.dialect, a.model.as_str()), ("gemini", "foo"));
    let pm = a.path_model.clone().expect("a path model");
    assert!(!pm.stream && !pm.json_array);
    let s = openai_lane("foo");
    let r = build(HOST, &a, &json(), &s, "p", "foo").expect("built");
    let far = body_json(&r.body);
    assert!(far.get("messages").is_some(), "{far}");
    assert_ne!(far.get("stream"), Some(&json!(true)), "{far}");
    let w = whole::translate(
        HOST,
        &gemini_from_openai(&a, "foo", false),
        200,
        &openai_ok_body(),
    );
    assert_eq!(w.end, WholeEnd::Delivered, "{:?}", w.refused);
    assert_eq!(w.answer.status, 200);
    let client = body_json(&w.answer.body);
    assert!(client.get("candidates").is_some(), "{client}");
    assert!(client.get("choices").is_none(), "{client}");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_path_model_injects_model_and_stream_into_body`.
/// 1.5.5 behaviour pinned: a path-model arrival carries the URL's model and stream flag in the
/// body: a streaming path `{"model":"foo","stream":true}`, a buffered path
/// `{"model":"bar","stream":false}`. RED if either member is missing or wrong.
#[test]
fn a_path_model_arrival_carries_the_urls_model_and_stream_both_ways() {
    for (target, model, stream) in [
        ("/v1beta/models/foo:streamGenerateContent", "foo", true),
        ("/v1beta/models/bar:generateContent", "bar", false),
    ] {
        let a = ok(
            target,
            &json(),
            br#"{"contents":[{"role":"user","parts":[{"text":"x"}]}]}"#,
        );
        for v in [body_json(&a.body), a.parsed.clone().expect("parsed")] {
            assert_eq!(v["model"], model, "{target}");
            assert_eq!(v["stream"], stream, "{target}");
        }
    }
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_malformed_path_no_colon_is_404`.
/// 1.5.5 behaviour pinned: a gemini path with no colon (`/v1beta/models/gemini-flash`) is a
/// gemini-shaped JSON 404, never served. RED if it is served or reads another status or type.
#[test]
fn a_colon_less_gemini_path_is_a_gemini_404() {
    let d = no(
        "/v1beta/models/gemini-flash",
        &json(),
        br#"{"contents":[]}"#,
    );
    assert_eq!(
        (d.why, d.status, d.envelope),
        (Decline::PathNotFound, 404, "gemini")
    );
    let r = declined(HOST, &d);
    assert_eq!(r.status, 404);
    assert_eq!(
        r.fields
            .iter()
            .find(|(n, _)| n == "content-type")
            .map(|(_, v)| v.as_slice()),
        Some(b"application/json".as_slice())
    );
    assert_eq!(body_json(&r.body)["error"]["status"], "NOT_FOUND");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_empty_model_is_404`.
/// 1.5.5 behaviour pinned: an empty model before the colon (`/v1beta/models/:generateContent`) is a
/// gemini 404, never routed. RED if it is served or reads another status.
#[test]
fn an_empty_gemini_model_is_a_404() {
    let d = no(
        "/v1beta/models/:generateContent",
        &json(),
        br#"{"contents":[]}"#,
    );
    assert_eq!((d.why, d.status), (Decline::PathNotFound, 404));
    assert_eq!(declined(HOST, &d).status, 404);
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1_surface_error_echoes_v1_not_v1beta`.
/// 1.5.5 behaviour pinned: an unsupported action on the stable surface
/// (`/v1/models/foo:countTokens`) is a 404 whose sentence echoes "API version v1," and never
/// "v1beta"; a colon-less `/v1/models/gemini-flash` is the OpenAI-shaped `not_found_error` 404.
/// RED if the version echo leaks v1beta, or the colon-less path reads another shape.
#[test]
fn the_stable_gemini_surface_echoes_v1_and_its_colon_less_path_is_openai_shaped() {
    let d = no("/v1/models/foo:countTokens", &json(), br#"{"contents":[]}"#);
    assert_eq!(d.status, 404);
    let (status, _, body) = rendered(&d);
    assert_eq!(status, 404);
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("API version v1,"), "{msg}");
    assert!(!msg.contains("v1beta"), "{msg}");

    let d = no("/v1/models/gemini-flash", &json(), br#"{"contents":[]}"#);
    let (status, _, body) = rendered(&d);
    assert_eq!(status, 404);
    assert_eq!(body["error"]["type"], "not_found_error", "{body}");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1beta_surface_error_still_echoes_v1beta`.
/// 1.5.5 behaviour pinned: an unsupported action on `/v1beta/models/foo:countTokens` is a 404 whose
/// sentence echoes "v1beta". RED if the echo differs.
#[test]
fn the_beta_gemini_surface_still_echoes_v1beta() {
    let d = no(
        "/v1beta/models/foo:countTokens",
        &json(),
        br#"{"contents":[]}"#,
    );
    let (status, _, body) = rendered(&d);
    assert_eq!(status, 404);
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("v1beta"), "{msg}");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1_no_action_returns_openai_shaped_404`.
/// 1.5.5 behaviour pinned, every leg: a colon-less `/v1/models/gpt-4o` and an OpenAI fine-tune id
/// with colons but no gemini action (`/v1/models/ft:gpt-3.5-turbo:my-org::abc`) are JSON 404s in
/// the OpenAI `not_found_error` envelope with no gemini `status`; a colon-less
/// `/v1beta/models/gemini-flash` keeps gemini's `status: NOT_FOUND`; an empty model
/// (`/v1beta/models/:generateContent`) and an empty action (`/v1beta/models/gemini-flash:`) both
/// fall to the "Invalid resource path" 404, never a routed model.
/// RED if any leg reads another status, shape or sentence.
#[test]
fn the_ambiguous_stable_prefix_reads_openai_and_the_beta_prefix_reads_gemini() {
    for target in [
        "/v1/models/gpt-4o",
        "/v1/models/ft:gpt-3.5-turbo:my-org::abc",
    ] {
        let d = no(target, &json(), br#"{"contents":[]}"#);
        let (status, _, body) = rendered(&d);
        assert_eq!(status, 404, "{target}");
        assert_eq!(body["error"]["type"], "not_found_error", "{target}: {body}");
        assert!(body["error"].get("status").is_none(), "{target}: {body}");
    }
    let d = no(
        "/v1beta/models/gemini-flash",
        &json(),
        br#"{"contents":[]}"#,
    );
    let (status, _, body) = rendered(&d);
    assert_eq!(status, 404);
    assert_eq!(body["error"]["status"], "NOT_FOUND", "{body}");
    for target in [
        "/v1beta/models/:generateContent",
        "/v1beta/models/gemini-flash:",
    ] {
        let d = no(target, &json(), br#"{"contents":[]}"#);
        let (status, _, body) = rendered(&d);
        assert_eq!(status, 404, "{target}");
        let msg = body["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.contains("Invalid resource path"), "{target}: {msg}");
    }
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_model_with_colon_splits_on_last_colon`.
/// 1.5.5 behaviour pinned: `/v1beta/models/tunedModels/abc:1:generateContent` names the model
/// `tunedModels/abc:1` (the split is on the LAST colon) and is routed to that model's far end.
/// RED if the model reads otherwise or the attempt is refused.
#[test]
fn a_gemini_model_with_a_colon_splits_on_the_last_colon() {
    let a = ok(
        "/v1beta/models/tunedModels/abc:1:generateContent",
        &json(),
        br#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#,
    );
    assert_eq!(a.model, "tunedModels/abc:1");
    let s = openai_lane("tunedModels/abc:1");
    assert!(build(HOST, &a, &json(), &s, "p", "tunedModels/abc:1").is_ok());
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_colon`.
/// 1.5.5 behaviour pinned: `%3A` decodes to `:`. RED if it does not.
#[test]
fn percent_decode_reads_an_encoded_colon() {
    assert_eq!(percent_decode("%3A"), ":");
    assert_eq!(
        percent_decode("anthropic.claude-3%3A0"),
        "anthropic.claude-3:0"
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_period_and_plain`.
/// 1.5.5 behaviour pinned: `%2E` decodes to `.` and a plain id passes unchanged. RED if not.
#[test]
fn percent_decode_reads_an_encoded_period_and_passes_plain_text() {
    assert_eq!(percent_decode("a%2Eb"), "a.b");
    assert_eq!(
        percent_decode("anthropic.claude-3-sonnet"),
        "anthropic.claude-3-sonnet"
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_malformed_escape_passes_through`.
/// 1.5.5 behaviour pinned: a `%` before non-hex digits is left verbatim. RED if dropped or decoded.
#[test]
fn percent_decode_leaves_a_malformed_escape_verbatim() {
    assert_eq!(percent_decode("%XY"), "%XY");
    assert_eq!(percent_decode("a%ZZb"), "a%ZZb");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_trailing_percent_is_safe`.
/// 1.5.5 behaviour pinned: a trailing `%`, or one with a single following byte, passes through
/// without reading past the end. RED if it panics or changes the bytes.
#[test]
fn percent_decode_passes_a_trailing_percent_safely() {
    assert_eq!(percent_decode("abc%"), "abc%");
    assert_eq!(percent_decode("abc%3"), "abc%3");
}

/// A body-model arrival refused for its model, as the caller reads it.
fn model_refusal(target: &str, body: &[u8]) -> (u16, Value) {
    let d = no(target, &json(), body);
    assert_eq!((d.why, d.status), (Decline::MissingModel, 400), "{target}");
    let (status, _, rendered_body) = rendered(&d);
    (status, rendered_body)
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_cohere_empty_model_is_400_native_envelope`.
/// 1.5.5 behaviour pinned: cohere `/v2/chat` with `"model": ""` is a 400 (not a 404) in cohere's
/// bare envelope: a top-level `message`, no `error` or `type`. RED if the status or shape differs.
#[test]
fn a_cohere_empty_model_is_coheres_400() {
    let (status, body) = model_refusal("/v2/chat", br#"{"model":"","messages":[]}"#);
    assert_eq!(status, 400);
    assert!(
        body.get("message").and_then(Value::as_str).is_some(),
        "{body}"
    );
    assert!(
        body.get("error").is_none() && body.get("type").is_none(),
        "{body}"
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_responses_empty_model_is_400_native_envelope`.
/// 1.5.5 behaviour pinned: responses with `"model": ""` is a 400 whose `error.type` is
/// `invalid_request_error`. RED if the status or type differs.
#[test]
fn a_responses_empty_model_is_an_invalid_request_400() {
    let (status, body) = model_refusal("/v1/responses", br#"{"model":"","input":"hi"}"#);
    assert_eq!(status, 400);
    assert_eq!(body["error"]["type"], "invalid_request_error", "{body}");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_openai_numeric_model_is_400_native_envelope`.
/// 1.5.5 behaviour pinned: openai with `"model": 42` is a 400 `invalid_request_error`, never
/// coerced to a name and answered 404. RED if the status or type differs.
#[test]
fn an_openai_numeric_model_is_an_invalid_request_400() {
    let (status, body) = model_refusal("/v1/chat/completions", br#"{"model":42,"messages":[]}"#);
    assert_eq!(status, 400);
    assert_eq!(body["error"]["type"], "invalid_request_error", "{body}");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_cohere_numeric_model_is_400_native_envelope`.
/// 1.5.5 behaviour pinned: cohere with `"model": null` is a 400 in cohere's bare envelope.
/// RED if the status or shape differs.
#[test]
fn a_cohere_null_model_is_coheres_400() {
    let (status, body) = model_refusal("/v2/chat", br#"{"model":null,"messages":[]}"#);
    assert_eq!(status, 400);
    assert!(
        body.get("message").and_then(Value::as_str).is_some(),
        "{body}"
    );
    assert!(
        body.get("error").is_none() && body.get("type").is_none(),
        "{body}"
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_responses_numeric_model_is_400_native_envelope`.
/// 1.5.5 behaviour pinned: responses with `"model": true` is a 400 `invalid_request_error`.
/// RED if the status or type differs.
#[test]
fn a_responses_bool_model_is_an_invalid_request_400() {
    let (status, body) = model_refusal("/v1/responses", br#"{"model":true,"input":"hi"}"#);
    assert_eq!(status, 400);
    assert_eq!(body["error"]["type"], "invalid_request_error", "{body}");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_non_object_body_is_400`.
/// 1.5.5 behaviour pinned: a top-level array to `/model/foo/converse` is a bedrock 400
/// `ValidationException` carrying `x-amzn-errortype`, never a panic or a 500.
/// RED if the status, the type or the header differs.
#[test]
fn a_bedrock_non_object_body_is_a_validation_400() {
    let d = no("/model/foo/converse", &json(), b"[1,2]");
    assert_eq!((d.why, d.status), (Decline::NotAnObject, 400));
    let r = declined(HOST, &d);
    assert_eq!(r.status, 400);
    assert!(r.fields.iter().any(|(n, _)| n == "x-amzn-errortype"));
    assert_eq!(body_json(&r.body)["__type"], "ValidationException");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_percent_encoded_model_id_converse_stream`.
/// 1.5.5 behaviour pinned: `/model/anthropic.claude-3%3Ahaiku/converse-stream` names the decoded
/// model `anthropic.claude-3:haiku`, streamed, routes to that model's far end, and a bedrock caller
/// streams back in the AWS eventstream framing. RED if the model is not decoded, the stream flag is
/// lost, the attempt is refused, or the framing differs.
#[test]
fn a_percent_encoded_bedrock_model_is_decoded_and_streamed() {
    let a = ok(
        "/model/anthropic.claude-3%3Ahaiku/converse-stream",
        &json(),
        br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#,
    );
    assert_eq!(
        (a.dialect, a.model.as_str()),
        ("bedrock", "anthropic.claude-3:haiku")
    );
    assert!(a.path_model.as_ref().is_some_and(|p| p.stream));
    let s = openai_lane("anthropic.claude-3:haiku");
    let r = build(HOST, &a, &json(), &s, "p", "anthropic.claude-3:haiku").expect("built");
    assert_eq!(body_json(&r.body)["stream"], true);
    assert_eq!(
        busbar_plane_llm::exchange::reply::wire::ingress_stream_content_type("bedrock"),
        Some("application/vnd.amazon.eventstream")
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_model_not_found_uses_native_message`.
/// 1.5.5 behaviour pinned: a gemini model nothing serves reads a 404 whose sentence is gemini's own
/// and names the path's version: "models/no-such-model is not found for API version v1beta, or is
/// not supported for the task you are trying to perform." on v1beta, the same with "v1" on the
/// stable surface; never the OpenAI "does not exist" copy. RED if either sentence differs.
#[test]
fn a_gemini_unknown_model_reads_geminis_versioned_sentence() {
    for (target, version) in [
        ("/v1beta/models/no-such-model:generateContent", "v1beta"),
        ("/v1/models/no-such-model:generateContent", "v1"),
    ] {
        let a = ok(target, &json(), br#"{"contents":[]}"#);
        let shaped = a
            .path_model
            .as_ref()
            .and_then(|p| p.model_not_found_message.clone());
        let message = model_not_found(&a.model, shaped.as_deref());
        let want = format!(
            "models/no-such-model is not found for API version {version}, or is not supported for the task you are trying to perform."
        );
        assert_eq!(message, want, "{target}");
        let r = kernel_refusal(HOST, "gemini", reason::NO_DESTINATION, 404, &message, 0);
        assert_eq!(r.status, 404);
        let body = body_json(&r.body);
        assert_eq!(body["error"]["message"], want.as_str(), "{target}");
        assert!(!message.contains("does not exist"), "{target}");
    }
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1_stable_stream_generate_content_alt_sse`.
/// 1.5.5 behaviour pinned: the stable `/v1/models/foo:streamGenerateContent?alt=sse` is served:
/// model `foo`, streamed, event-stream framing (no JSON-array key in the body), and the openai far
/// end is asked to stream. RED if the stable alias is refused or the facts differ.
#[test]
fn the_stable_gemini_surface_streams_events_with_alt_sse() {
    let a = ok(
        "/v1/models/foo:streamGenerateContent?alt=sse",
        &json(),
        br#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#,
    );
    assert_eq!((a.dialect, a.model.as_str()), ("gemini", "foo"));
    let pm = a.path_model.clone().expect("a path model");
    assert!(pm.stream && !pm.json_array);
    assert!(body_json(&a.body)
        .get("__busbar_gemini_json_array")
        .is_none());
    let r = build(HOST, &a, &json(), &openai_lane("foo"), "p", "foo").expect("built");
    assert_eq!(body_json(&r.body)["stream"], true);
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1_stable_stream_generate_content_no_alt_sse`.
/// 1.5.5 behaviour pinned: the stable `/v1/models/foo:streamGenerateContent` without `alt=sse` is a
/// JSON-array caller: the caller reads `application/json`, an array of gemini chunks
/// (`candidates`, never `choices`). RED if the framing or the chunk shape differs.
#[test]
fn the_stable_gemini_surface_without_alt_sse_reads_a_json_array() {
    let a = ok(
        "/v1/models/foo:streamGenerateContent",
        &json(),
        br#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#,
    );
    let pm = a.path_model.clone().expect("a path model");
    assert!(pm.stream && pm.json_array);
    let w = whole::translate(
        HOST,
        &gemini_from_openai(&a, "foo", true),
        200,
        &openai_ok_body(),
    );
    assert_eq!(w.end, WholeEnd::Delivered, "{:?}", w.refused);
    assert_eq!(
        w.answer
            .fields
            .iter()
            .find(|(n, _)| n == "content-type")
            .map(|(_, v)| v.as_slice()),
        Some(b"application/json".as_slice())
    );
    let v = body_json(&w.answer.body);
    let chunks = v.as_array().expect("a JSON array");
    assert!(!chunks.is_empty());
    assert!(
        chunks.iter().any(|chunk| chunk.get("candidates").is_some()),
        "{v}"
    );
    assert!(
        chunks.iter().all(|chunk| chunk.get("choices").is_none()),
        "{v}"
    );
}

/// Rehomes `crates/busbar-llm/src/tests/arrival_tests.rs::test_query_has_alt_sse`.
/// 1.5.5 behaviour pinned: only a genuine `alt=sse` pair selects event-stream framing, wherever it
/// stands in the query (`alt=sse`, `key=abc&alt=sse`, `alt=sse&key=abc`); `alt=json`, an empty
/// query, `foo=alt=sse` and a bare `alt` all leave the JSON-array framing.
/// RED if any of the seven queries reads the other way.
#[test]
fn only_a_genuine_alt_sse_pair_selects_event_framing() {
    for (query, events) in [
        ("alt=sse", true),
        ("key=abc&alt=sse", true),
        ("alt=sse&key=abc", true),
        ("alt=json", false),
        ("", false),
        ("foo=alt=sse", false),
        ("alt", false),
    ] {
        let a = ok(
            &format!("/v1beta/models/p:streamGenerateContent?{query}"),
            &json(),
            br#"{"contents":[]}"#,
        );
        let pm = a.path_model.expect("a path model");
        assert!(pm.stream, "{query}");
        assert_eq!(pm.json_array, !events, "{query:?}");
    }
}

/// Rehomes `crates/busbar-llm/src/tests/arrival_tests.rs::test_gemini_api_version_prefix_mapping`.
/// 1.5.5 behaviour pinned: the version gemini's sentences echo is `v1` on the stable surface,
/// `v1beta` on the beta surface, and `v1beta` for any other prefix.
/// RED if any of the three echoes differs.
#[test]
fn geminis_version_echo_follows_the_path_prefix() {
    for (target, version) in [
        ("/v1/models/foo:generateContent", "v1"),
        ("/v1beta/models/foo:generateContent", "v1beta"),
        ("/weird/models/foo:generateContent", "v1beta"),
    ] {
        let a = ok(target, &json(), br#"{"contents":[]}"#);
        let copy = a
            .path_model
            .and_then(|p| p.model_not_found_message)
            .expect("gemini's own copy");
        assert!(
            copy.contains(&format!("for API version {version},")),
            "{target}: {copy}"
        );
    }
}

/// Rehomes `crates/busbar-llm/src/tests/arrival_tests.rs::the_gemini_parse_reads_its_own_url_space`.
/// 1.5.5 behaviour pinned: `/v1beta/models/p:generateContent` reads model `p`, chat, no stream,
/// no JSON-array framing and gemini's copy "models/p is not found for API version v1beta, or is not
/// supported for the task you are trying to perform."; `:streamGenerateContent` streams with the
/// array framing, and with `alt=sse` without it; an unknown model is still a well-formed URL whose
/// copy names it; the stable prefix versions its copy "API version v1,"; `:countTokens` and a
/// colon-less path are refused before routing. RED if any fact or refusal differs.
#[test]
fn the_gemini_url_space_reads_every_fact() {
    let read = |target: &str| ok(target, &json(), br#"{"contents":[]}"#);
    let a = read("/v1beta/models/p:generateContent");
    assert_eq!(a.model, "p");
    assert_eq!(a.operation, OpVerb::CHAT);
    let pm = a.path_model.expect("a path model");
    assert!(!pm.stream && !pm.json_array);
    assert_eq!(
        pm.model_not_found_message.as_deref(),
        Some("models/p is not found for API version v1beta, or is not supported for the task you are trying to perform.")
    );
    let pm = read("/v1beta/models/p:streamGenerateContent")
        .path_model
        .expect("a path model");
    assert!(pm.stream && pm.json_array);
    let pm = read("/v1beta/models/p:streamGenerateContent?alt=sse")
        .path_model
        .expect("a path model");
    assert!(pm.stream && !pm.json_array);
    let a = read("/v1beta/models/no-such-model:generateContent");
    assert_eq!(a.model, "no-such-model");
    assert_eq!(
        a.path_model.and_then(|p| p.model_not_found_message).as_deref(),
        Some("models/no-such-model is not found for API version v1beta, or is not supported for the task you are trying to perform.")
    );
    let copy = read("/v1/models/p:generateContent")
        .path_model
        .and_then(|p| p.model_not_found_message)
        .expect("a copy");
    assert!(copy.contains("API version v1,"), "{copy}");
    for target in ["/v1beta/models/p:countTokens", "/v1beta/models/p"] {
        let d = no(target, &json(), br#"{"contents":[]}"#);
        assert_eq!((d.why, d.status), (Decline::PathNotFound, 404), "{target}");
    }
}

/// Rehomes `crates/busbar-llm/src/tests/arrival_tests.rs::the_bedrock_parse_reads_its_own_url_space`.
/// 1.5.5 behaviour pinned: `/model/p/converse` reads model `p`, chat, no stream, no array framing,
/// no copy of its own; `/converse-stream` streams; `/invoke` names only the model and leaves the
/// operation to the body (a body naming `inputText` arrives as a body-model request for `p`, a
/// body naming no supported operation is the 400); `/invoke-with-response-stream` and `/nope` are
/// the router's 404. RED if any fact or refusal differs.
#[test]
fn the_bedrock_url_space_reads_every_fact() {
    let converse = br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#;
    let a = ok("/model/p/converse", &json(), converse);
    assert_eq!(a.model, "p");
    assert_eq!(a.operation, OpVerb::CHAT);
    let pm = a.path_model.expect("a path model");
    assert!(!pm.stream && !pm.json_array);
    assert_eq!(pm.model_not_found_message, None);
    let a = ok("/model/p/converse-stream", &json(), converse);
    assert_eq!(a.model, "p");
    let pm = a.path_model.expect("a path model");
    assert!(pm.stream && !pm.json_array);

    let a = ok("/model/p/invoke", &json(), br#"{"inputText":"hi"}"#);
    assert_eq!(a.model, "p");
    assert!(a.path_model.is_none(), "the operation is the body's");
    let d = no("/model/p/invoke", &json(), converse);
    assert_eq!((d.why, d.status), (Decline::InvokeBody, 400));
    assert_eq!(
        d.message,
        "InvokeModel body is not a supported operation (expected inputText or textToImageParams)."
    );
    for target in ["/model/p/invoke-with-response-stream", "/model/p/nope"] {
        let d = no(target, &json(), converse);
        assert_eq!((d.why, d.status), (Decline::NoResource, 404), "{target}");
    }
}

fn shim_key() -> &'static str {
    busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == "gemini")
        .and_then(|d| d.array_stream_shim_key)
        .expect("gemini declares its array-stream key")
}

/// The handler 1.5.5's lookup resolves for a dialect's chat.
fn live_chat_handler(dialect: &str) -> &'static dyn OperationHandler {
    busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == dialect)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(OpVerb::CHAT))
        .expect("every dialect serves chat")
}

fn same_handler(x: &dyn OperationHandler, y: &dyn OperationHandler) -> bool {
    std::ptr::eq(
        x as *const dyn OperationHandler as *const u8,
        y as *const dyn OperationHandler as *const u8,
    )
}

/// Rehomes `crates/busbar-llm/src/tests/arrival_tests.rs::the_url_facts_drive_the_two_steps_to_the_live_paths_answer`.
/// 1.5.5 behaviour pinned: for gemini AND bedrock URL models, streamed and buffered, the arrival's
/// body is exactly the live splice of the URL's facts (model, stream, and gemini's array key when
/// asked) into the caller's bytes, it reads as the caller's document with those members set, and
/// the handler resolved is the live lookup's. RED if the bytes, the document or the handler differ.
#[test]
fn the_url_facts_land_on_the_live_splice_and_the_live_handler() {
    let gemini = br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;
    let bedrock = br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#;
    for (dialect, target, body, stream, shim) in [
        (
            "gemini",
            "/v1beta/models/p:streamGenerateContent",
            &gemini[..],
            true,
            true,
        ),
        (
            "gemini",
            "/v1beta/models/p:generateContent",
            &gemini[..],
            false,
            false,
        ),
        (
            "bedrock",
            "/model/p/converse-stream",
            &bedrock[..],
            true,
            false,
        ),
        ("bedrock", "/model/p/converse", &bedrock[..], false, false),
    ] {
        let a = ok(target, &json(), body);
        assert_eq!(a.dialect, dialect);
        let live = splice_path_facts(body, "p", stream, shim.then(shim_key)).expect("a document");
        assert_eq!(a.body, live, "{target}: the bytes are the live splice");
        let mut doc = body_json(body);
        let obj = doc.as_object_mut().expect("a document");
        obj.insert("model".into(), json!("p"));
        obj.insert("stream".into(), json!(stream));
        if shim {
            obj.insert(shim_key().into(), json!(true));
        }
        assert_eq!(body_json(&a.body), doc, "{target}");
        assert_eq!(a.parsed.as_ref(), Some(&doc), "{target}");
        let resolved = busbar_plane_llm::exchange::handler_of(&a).expect("a handler");
        assert!(
            same_handler(resolved, live_chat_handler(dialect)),
            "{target}"
        );
    }
}

/// The recorded request corpus (the codec's golden request bodies, every one 1.5.5 recorded).
fn corpus() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/tests/proto/golden");
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .expect("the recorded request corpus is readable")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("req_") && n.ends_with(".json"))
        .map(|n| {
            let bytes = std::fs::read(dir.join(&n)).expect("a recording is readable");
            (n, bytes)
        })
        .collect();
    out.sort();
    assert!(out.len() > 40, "the corpus moved or shrank: {}", out.len());
    out
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::the_path_model_step_injects_the_members_into_the_callers_bytes`.
/// 1.5.5 behaviour pinned: for every recorded request, through a gemini AND a bedrock URL model,
/// the arrival's body reads as the caller's document with `model` and `stream` set, and a request
/// that named neither keeps every one of its own bytes after the opening brace, in order (a
/// re-serialization would sort and respace them). RED if the document or the caller's bytes move.
#[test]
fn every_recorded_request_keeps_its_bytes_under_the_path_model_splice() {
    for (name, body) in corpus() {
        for target in [
            "/v1beta/models/pinned-model:streamGenerateContent?alt=sse",
            "/model/pinned-model/converse-stream",
        ] {
            let a = ok(target, &json(), &body);
            let mut doc = body_json(&body);
            let obj = doc
                .as_object_mut()
                .expect("a recorded request is a document");
            let names_neither = !obj.contains_key("model") && !obj.contains_key("stream");
            obj.insert("model".into(), json!("pinned-model"));
            obj.insert("stream".into(), json!(true));
            assert_eq!(body_json(&a.body), doc, "{name} {target}");
            assert_eq!(a.parsed.as_ref(), Some(&doc), "{name} {target}");
            if names_neither {
                let brace = body.iter().position(|b| *b == b'{').expect("an object");
                assert!(
                    a.body.ends_with(&body[brace + 1..]),
                    "{name} {target}: the caller's own bytes moved"
                );
            }
        }
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::the_url_model_and_stream_flag_win_over_the_body`.
/// 1.5.5 behaviour pinned: a body naming `model: from-the-body` and `stream: false` under a URL
/// naming `from-the-url` and a stream reads the URL's model and `stream: true`, and every other
/// member (`x: 1`) survives, on gemini and bedrock alike. RED if the body's own values win.
#[test]
fn the_urls_model_and_stream_win_over_the_bodys() {
    let body = br#"{"model":"from-the-body","stream":false,"x":1}"#;
    for target in [
        "/v1beta/models/from-the-url:streamGenerateContent?alt=sse",
        "/model/from-the-url/converse-stream",
    ] {
        let a = ok(target, &json(), body);
        assert_eq!(a.model, "from-the-url", "{target}");
        for v in [body_json(&a.body), a.parsed.clone().expect("parsed")] {
            assert_eq!(v["model"], "from-the-url", "{target}");
            assert_eq!(v["stream"], true, "{target}");
            assert_eq!(v["x"], 1, "{target}");
        }
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::the_array_stream_shim_is_spliced_only_when_asked`.
/// 1.5.5 behaviour pinned: busbar's array-stream key is spliced only when the JSON-array framing is
/// asked (gemini streamed without `alt=sse`) and only for a dialect that declares one; a dialect
/// with no key (bedrock, and every other) is unchanged whether asked or not.
/// RED if the key appears unasked, is missing when asked, or a keyless dialect changes shape.
#[test]
fn the_array_stream_key_is_spliced_only_when_asked() {
    let key = shim_key();
    let asked = ok(
        "/v1beta/models/m:streamGenerateContent",
        &json(),
        br#"{"a":1}"#,
    );
    assert_eq!(body_json(&asked.body)[key], true);
    assert_eq!(
        asked.parsed.as_ref().and_then(|v| v.get(key)),
        Some(&json!(true))
    );
    let unasked = ok(
        "/v1beta/models/m:streamGenerateContent?alt=sse",
        &json(),
        br#"{"a":1}"#,
    );
    assert!(body_json(&unasked.body).get(key).is_none());
    assert!(unasked
        .parsed
        .as_ref()
        .is_some_and(|v| v.get(key).is_none()));
    let keyed: Vec<&str> = busbar_plane_llm::codec::DECLS
        .iter()
        .filter(|d| d.array_stream_shim_key.is_some())
        .map(|d| d.name)
        .collect();
    assert_eq!(
        keyed,
        ["gemini"],
        "only gemini declares an array-stream key"
    );
    let bedrock = ok("/model/m/converse-stream", &json(), br#"{"a":1}"#);
    assert!(body_json(&bedrock.body).get(key).is_none());
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::an_absent_content_type_is_read_as_json`.
/// 1.5.5 behaviour pinned: an arrival with no content type is read as JSON (its content type empty,
/// its body parsed), so a header-less client is served. RED if it is refused or left unparsed.
#[test]
fn an_arrival_with_no_content_type_is_read_as_json() {
    let a = ok("/v1/chat/completions", &head(&[]), br#"{"model":"m"}"#);
    assert_eq!(a.content_type, "");
    assert!(a.parsed.is_some());
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::a_json_content_type_with_parameters_still_parses`.
/// 1.5.5 behaviour pinned: `application/json; charset=utf-8` is JSON (the read is a prefix match).
/// RED if the body is left unparsed or refused.
#[test]
fn a_json_content_type_with_a_charset_still_parses() {
    let a = ok(
        "/v1/chat/completions",
        &head(&[("content-type", "application/json; charset=utf-8")]),
        br#"{"model":"m"}"#,
    );
    assert!(a.parsed.is_some());
    assert_eq!(a.model, "m");
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::the_refusal_set_is_three_and_they_do_not_collide`.
/// 1.5.5 behaviour pinned: the arrival refusal set is three (the parse refusal, the non-object
/// refusal, the re-serialization guard), each a 400 `invalid_request_error` with its own sentence;
/// the first two are driven from real arrivals, the guard (unreachable) by its sentence.
/// RED if a sentence repeats, or a member reads another status or kind.
#[test]
fn the_arrival_refusal_set_is_three_distinct_400s() {
    let parse = no("/v1beta/models/m:generateContent", &json(), b"{not json");
    let not_object = no("/v1beta/models/m:generateContent", &json(), b"[1]");
    assert_eq!(parse.why, Decline::BodyParse);
    assert_eq!(not_object.why, Decline::NotAnObject);
    let mut sentences = vec![
        parse.message.to_string(),
        not_object.message.to_string(),
        "The request body could not be processed.".to_string(),
    ];
    for d in [&parse, &not_object] {
        assert_eq!((d.status, d.kind), (400, "invalid_request_error"));
    }
    assert_eq!(
        sentences,
        [
            "We could not parse the JSON body of your request.",
            "Request body must be a JSON object.",
            "The request body could not be processed."
        ]
    );
    sentences.sort_unstable();
    sentences.dedup();
    assert_eq!(sentences.len(), 3, "two reasons share one sentence");
}

/// Rehomes `crates/busbar-llm/src/unit/tests/audit.rs::audit_refused_matches_the_live_rejected_terminal`.
/// 1.5.5 behaviour pinned: a refusal before any forward (a missing model) answers 400 with the
/// same bytes whichever path renders it, and it is an arrival refusal: the kernel answers it before
/// a unit is admitted, so nothing was charged and nothing is refunded. The plane's half is pinned
/// here: the arrival refuses (no unit), and its rendering is byte-for-byte the released 400.
/// RED if the missing model is admitted, or the rendered status or bytes differ.
#[test]
fn a_pre_forward_refusal_renders_the_released_400_before_any_unit() {
    let d = no("/v1/chat/completions", &json(), br#"{"messages":[]}"#);
    assert_eq!(
        (d.why, d.status, d.envelope),
        (Decline::MissingModel, 400, "openai")
    );
    let unit = declined(HOST, &d);
    let live = render(
        HOST,
        "openai",
        400,
        "invalid_request_error",
        "Missing required parameter: 'model'.",
        0,
    );
    assert_eq!(unit, live);
    assert_eq!(unit.status, 400);
    assert_eq!(
        body_json(&unit.body),
        json!({ "error": {
            "code": null,
            "message": "Missing required parameter: 'model'.",
            "param": null,
            "type": "invalid_request_error"
        }})
    );
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::every_recorded_request_decodes_to_the_live_paths_model`.
/// 1.5.5 behaviour pinned: for every recorded request, the arrival reads exactly the model 1.5.5
/// routed (the body's non-empty string `model`), and every request 1.5.5 refused for want of one
/// is refused 400 `MissingModel`. RED if any recording reads another model or another answer.
#[test]
fn every_recorded_request_reads_the_released_model() {
    for (name, body) in corpus() {
        let live = body_json(&body)
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string);
        match live {
            Some(m) if !m.is_empty() => {
                assert_eq!(
                    ok("/v1/chat/completions", &json(), &body).model,
                    m,
                    "{name}"
                )
            }
            _ => {
                let d = no("/v1/chat/completions", &json(), &body);
                assert_eq!((d.why, d.status), (Decline::MissingModel, 400), "{name}");
            }
        }
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::a_url_model_wins_over_the_body`.
/// 1.5.5 behaviour pinned: a model named in the URL wins over one the body names, on gemini,
/// bedrock and the named anthropic surface. RED if the body's model is read.
#[test]
fn a_url_model_wins_over_the_bodys() {
    for (target, body) in [
        (
            "/v1beta/models/from-the-url:generateContent",
            &br#"{"model":"from-the-body"}"#[..],
        ),
        (
            "/model/from-the-url/converse",
            &br#"{"model":"from-the-body"}"#[..],
        ),
        (
            "/from-the-url/v1/messages",
            &br#"{"model":"from-the-body","max_tokens":1,"messages":[]}"#[..],
        ),
    ] {
        assert_eq!(ok(target, &json(), body).model, "from-the-url", "{target}");
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::a_multipart_body_with_no_model_field_is_a_missing_model`.
/// 1.5.5 behaviour pinned: a multipart arrival with no `model` part is refused 400 MissingModel.
/// RED if it is served or refused otherwise.
#[test]
fn a_multipart_arrival_with_no_model_part_is_a_missing_model() {
    let h = head(&[("content-type", "multipart/form-data; boundary=zz")]);
    let d = no(
        "/v1/audio/transcriptions",
        &h,
        b"--zz\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nxx\r\n--zz--",
    );
    assert_eq!((d.why, d.status), (Decline::MissingModel, 400));
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::the_ladder_floor_catches_every_shape_of_no_model`.
/// 1.5.5 behaviour pinned: every shape of no model (`{}`, `""`, `null`, `7`, a top-level array, a
/// JSON string) is refused 400 MissingModel; an EMPTY URL model on a path-model dialect is not
/// refused at arrival (bedrock `/model//converse` arrives with model ``, resolution's to answer).
/// RED if any shape is served, or the empty URL model is refused at the door.
#[test]
fn every_shape_of_no_model_is_the_missing_model_400() {
    for raw in [
        &br#"{}"#[..],
        &br#"{"model":""}"#[..],
        &br#"{"model":null}"#[..],
        &br#"{"model":7}"#[..],
        &br#"[]"#[..],
        &br#""a string""#[..],
    ] {
        let d = no("/v1/chat/completions", &json(), raw);
        assert_eq!(
            (d.why, d.status),
            (Decline::MissingModel, 400),
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
    let a = ok(
        "/model//converse",
        &json(),
        br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#,
    );
    assert_eq!(a.model, "", "the empty name reaches resolution intact");
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::the_two_handler_misses_carry_the_live_arms_distinct_bytes`.
/// 1.5.5 behaviour pinned: the protocol miss ("This protocol does not support that operation.")
/// and the endpoint miss ("This endpoint does not support that operation.") are both 404
/// `not_found_error`, and in every dialect they render different bytes.
/// RED if the two collapse into one, or either sentence or status differs.
#[test]
fn the_two_operation_misses_render_distinct_404s_in_every_dialect() {
    for dialect in [
        "anthropic",
        "openai",
        "gemini",
        "bedrock",
        "responses",
        "cohere",
    ] {
        let protocol_miss = render(
            HOST,
            dialect,
            404,
            "not_found_error",
            "This protocol does not support that operation.",
            0,
        );
        let endpoint_miss = declined(
            HOST,
            &Declined {
                why: Decline::UnsupportedOperation,
                status: 404,
                envelope: dialect,
                kind: "not_found_error",
                message: "This endpoint does not support that operation.".into(),
                entry: None,
            },
        );
        assert_eq!((protocol_miss.status, endpoint_miss.status), (404, 404));
        assert_ne!(protocol_miss.body, endpoint_miss.body, "{dialect}");
        let text = String::from_utf8_lossy(&endpoint_miss.body);
        assert!(
            text.contains("This endpoint does not support that operation."),
            "{text}"
        );
        let text = String::from_utf8_lossy(&protocol_miss.body);
        assert!(
            text.contains("This protocol does not support that operation."),
            "{text}"
        );
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::the_body_entry_point_answers_the_handler_miss_before_the_parse_miss`.
/// 1.5.5 behaviour pinned: on the body-model entry point the operation lookup runs BEFORE the
/// parse, so a request that names no served operation AND carries a malformed body answers the
/// 404, never the parse 400: a path a dialect claims but resolves no operation for (cohere's
/// `/v1/chat`), and a path no dialect claims. RED if either answers the 400.
#[test]
fn a_body_model_arrival_answers_the_operation_miss_before_the_parse_miss() {
    for target in ["/v1/chat", "/nowhere"] {
        let d = no(target, &json(), b"{ not json");
        assert_eq!((d.why, d.status), (Decline::NoResource, 404), "{target}");
    }
    let d = no("/v1/chat/completions", &json(), b"{ not json");
    assert_eq!(
        (d.why, d.status),
        (Decline::BodyParse, 400),
        "a served operation parses"
    );
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::the_path_model_entry_point_answers_the_parse_miss_first`.
/// 1.5.5 behaviour pinned: the path-model entry point composes the other way round: the body is
/// parsed first, so a malformed body at a gemini or bedrock URL answers the parse 400.
/// RED if either answers otherwise.
#[test]
fn a_path_model_arrival_answers_the_parse_miss_first() {
    for target in ["/v1beta/models/m:generateContent", "/model/m/converse"] {
        let d = no(target, &json(), b"{ not json");
        assert_eq!((d.why, d.status), (Decline::BodyParse, 400), "{target}");
        assert_eq!(
            d.message,
            "We could not parse the JSON body of your request."
        );
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::the_refusal_set_is_three_and_they_do_not_collide` (the decode set).
/// 1.5.5 behaviour pinned: the decode refusals are the protocol miss 404, the endpoint miss 404
/// and the missing model 400, three distinct sentences; the missing model is driven from a real
/// arrival. RED if a status differs or two sentences collide.
#[test]
fn the_decode_refusal_set_is_two_404s_and_a_400_with_distinct_sentences() {
    let missing = no("/v1/chat/completions", &json(), br#"{"messages":[]}"#);
    assert_eq!((missing.why, missing.status), (Decline::MissingModel, 400));
    let mut set = vec![
        (
            404,
            "This protocol does not support that operation.".to_string(),
        ),
        (
            404,
            "This endpoint does not support that operation.".to_string(),
        ),
        (missing.status, missing.message.to_string()),
    ];
    assert_eq!(
        set[2],
        (400, "Missing required parameter: 'model'.".to_string())
    );
    set.sort();
    set.dedup_by(|next, kept| next.1 == kept.1);
    assert_eq!(set.len(), 3, "two reasons share one sentence");
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::the_whole_step_resolves_both_facts_for_a_recorded_request`.
/// 1.5.5 behaviour pinned: for every recorded request that names a model in its body, the arrival
/// resolves a non-empty model and a chat handler, and the same model named in a URL (the path-model
/// spelling) arrives as the same model with a chat handler too. RED if either spelling loses the
/// model or resolves no handler.
#[test]
fn every_recorded_body_model_resolves_the_same_model_both_spellings() {
    let mut seen = 0;
    for (name, body) in corpus() {
        let Some(model) = body_json(&body)
            .get("model")
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
            .map(str::to_string)
        else {
            continue;
        };
        let a = ok("/v1/chat/completions", &json(), &body);
        assert_eq!(a.model, model, "{name}");
        assert!(
            busbar_plane_llm::exchange::handler_of(&a).is_some(),
            "{name}"
        );
        let p = ok(
            &format!("/model/{model}/converse"),
            &json(),
            br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#,
        );
        assert_eq!(p.model, a.model, "{name}");
        assert_eq!(p.operation, OpVerb::CHAT, "{name}");
        assert!(
            busbar_plane_llm::exchange::handler_of(&p).is_some(),
            "{name}"
        );
        seen += 1;
    }
    assert!(seen > 0, "the corpus has a body-model request");
}

/// Q128 arch u59: A HOOK'S REWRITE IS SPLICED INTO THE CALLER'S BYTES, never re-serialized (the
/// OWNER 2026-10-02 LLM DIALECT FIDELITY RULE: "hook `rw` edits, spliced per changed block"). The
/// body arrives with its members out of sorted order, spaced, with a number spelled `1.50` and an
/// escaped slash; only `messages` changes, and every other member's bytes reach the far end as the
/// caller wrote them. RED: the whole body was re-serialized (keys sorted, spacing dropped, `1.50`
/// read back as `1.5`, the escape normalized).
#[test]
fn a_hook_rewrite_splices_only_the_members_it_changes() {
    use busbar_plane_llm::exchange::project::apply_rewrite;
    let body = br#"{ "temperature" : 1.50, "model": "m0",
  "metadata": {"z": "a\/b", "a": 1},
  "messages": [{"role": "user", "content": "x"}] }"#;
    let mut arrived = ok("/v1/chat/completions", &json(), body);
    let rewrite = br#"{"messages":[{"role":"user","content":"compressed"}],"tools":[]}"#;
    let bytes = apply_rewrite(&mut arrived, rewrite).expect("the rewrite applies");
    let text = String::from_utf8(bytes.clone()).expect("utf-8");
    assert!(
        text.starts_with(r#"{ "temperature" : 1.50, "model": "m0","#),
        "untouched members keep their bytes and order: {text}"
    );
    assert!(
        text.contains(r#""metadata": {"z": "a\/b", "a": 1},"#),
        "an untouched object keeps its bytes: {text}"
    );
    let v: Value = serde_json::from_slice(&bytes).expect("the spliced body is JSON");
    assert_eq!(v["messages"][0]["content"], "compressed");
    assert_eq!(arrived.body, bytes, "the arrival's body is the spliced one");
}
