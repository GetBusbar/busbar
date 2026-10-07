// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The arrival cases the retired engine crate's tests pinned, ported onto the plane's own `arrive`
//! and its refusal renderer: the URL-model dialects' paths, the percent-decoding of a path model,
//! the content types a body is read as JSON under, the refusals a path or body earns, and the
//! model every recorded request names. Each test cites the legacy test it ports.

use busbar_plane_llm::exchange::arrive::*;
use busbar_plane_llm::exchange::refuse::{declined, Rendered};
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

/// The host's entropy, so a dialect that mints a request id mints one.
fn entropy() {
    busbar_contract::codec::install_entropy_source(|out| {
        out.fill(7);
        true
    });
}

/// The refusal a refused arrival renders, its body read as JSON.
fn rendered(target: &str, h: &[(&[u8], &[u8])], body: &[u8]) -> (Rendered, Value) {
    entropy();
    let r = declined(&no(target, h, body));
    let v: Value = serde_json::from_slice(&r.body).expect("a refusal body is JSON");
    (r, v)
}

fn field<'a>(r: &'a Rendered, name: &str) -> Option<&'a [u8]> {
    r.fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
}

fn message(v: &Value) -> &str {
    v.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// An InvokeModel body matching no recognised shape is refused at arrival, 400, in the bedrock
/// envelope (the counter half is the door's,
/// `serve_door_exchange_ported::a_refused_arrival_is_counted_as_an_unresolved_client_error`).
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_invoke_unresolvable_body_is_observable`.
#[test]
fn an_invoke_body_of_no_known_shape_is_refused_400() {
    let d = no(
        "/model/amazon.titan-embed-text-v1/invoke",
        &json(),
        br#"{"nonsense":1}"#,
    );
    assert_eq!(
        (d.why, d.status, d.envelope),
        (Decline::InvokeBody, 400, "bedrock")
    );
    let (r, v) = rendered(
        "/model/amazon.titan-embed-text-v1/invoke",
        &json(),
        br#"{"nonsense":1}"#,
    );
    assert_eq!(r.status, 400);
    assert_eq!(v["__type"], "ValidationException", "{v}");
}

/// An unsupported action on the STABLE `/v1/models` surface echoes `v1` (never `v1beta`) in the
/// native not-found sentence; a colon-less `/v1/models/{id}` is the shared model-retrieve shape and
/// answers the `not_found_error` envelope.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1_surface_error_echoes_v1_not_v1beta`
/// and `crates/busbar-llm/src/tests/arrival_tests.rs::test_gemini_api_version_prefix_mapping` (the
/// version each prefix echoes; the helper's own fallback arm is unreachable through an arrival,
/// whose gemini paths all start with one of the two prefixes).
#[test]
fn an_unsupported_action_on_the_stable_surface_echoes_v1() {
    let (r, v) = rendered("/v1/models/foo:countTokens", &json(), br#"{"contents":[]}"#);
    assert_eq!(r.status, 404);
    let msg = message(&v);
    assert!(
        msg.contains("API version v1,") || msg.contains("API version v1 "),
        "the stable surface echoes v1: {msg}"
    );
    assert!(!msg.contains("v1beta"), "never v1beta: {msg}");

    let (r, v) = rendered("/v1/models/gemini-flash", &json(), br#"{"contents":[]}"#);
    assert_eq!(r.status, 404);
    assert_eq!(
        v.pointer("/error/type").and_then(Value::as_str),
        Some("not_found_error"),
        "{v}"
    );
}

/// The preview `/v1beta/models` surface still echoes `v1beta`.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1beta_surface_error_still_echoes_v1beta`
/// (and the `v1beta` arm of `crates/busbar-llm/src/tests/arrival_tests.rs::test_gemini_api_version_prefix_mapping`).
#[test]
fn an_unsupported_action_on_the_preview_surface_echoes_v1beta() {
    let (r, v) = rendered(
        "/v1beta/models/foo:countTokens",
        &json(),
        br#"{"contents":[]}"#,
    );
    assert_eq!(r.status, 404);
    assert!(message(&v).contains("v1beta"), "{v}");
}

/// The shared stable `/v1/models/{id}` prefix: a colon-less id, or one whose colons are no action
/// suffix (a fine-tune id), answers the `not_found_error` envelope with no vendor `status` member;
/// the preview surface stays in its own native shape; a colon with an empty model or an empty action
/// is no model:action split and reads the path's own not-found sentence.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1_no_action_returns_openai_shaped_404`.
#[test]
fn the_shared_stable_models_prefix_answers_the_not_found_envelope() {
    let (r, v) = rendered("/v1/models/gpt-4o", &json(), br#"{"contents":[]}"#);
    assert_eq!(r.status, 404);
    assert_eq!(
        field(&r, "content-type"),
        Some(b"application/json".as_slice())
    );
    assert_eq!(
        v.pointer("/error/type").and_then(Value::as_str),
        Some("not_found_error"),
        "{v}"
    );
    assert!(v.pointer("/error/status").is_none(), "{v}");

    let (r, v) = rendered(
        "/v1/models/ft:gpt-3.5-turbo:my-org::abc",
        &json(),
        br#"{"contents":[]}"#,
    );
    assert_eq!(r.status, 404);
    assert_eq!(
        v.pointer("/error/type").and_then(Value::as_str),
        Some("not_found_error"),
        "a fine-tune id is no action: {v}"
    );

    let (r, v) = rendered(
        "/v1beta/models/gemini-flash",
        &json(),
        br#"{"contents":[]}"#,
    );
    assert_eq!(r.status, 404);
    assert_eq!(
        v.pointer("/error/status").and_then(Value::as_str),
        Some("NOT_FOUND"),
        "{v}"
    );

    for target in [
        "/v1beta/models/:generateContent",
        "/v1beta/models/gemini-flash:",
    ] {
        let (r, v) = rendered(target, &json(), br#"{"contents":[]}"#);
        assert_eq!(r.status, 404, "{target}");
        assert!(
            message(&v).contains("Invalid resource path"),
            "{target}: an empty side of the colon is no split: {v}"
        );
    }
}

/// A model id that itself carries a colon splits on the LAST colon.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_model_with_colon_splits_on_last_colon`.
#[test]
fn a_colon_bearing_model_splits_on_the_last_colon() {
    let a = ok(
        "/v1beta/models/tunedModels/abc:1:generateContent",
        &json(),
        br#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#,
    );
    assert_eq!(
        (a.dialect, a.model.as_str()),
        ("gemini", "tunedModels/abc:1")
    );
}

/// `%3A` decodes to a colon.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_colon`.
#[test]
fn percent_decode_turns_an_escaped_colon_into_a_colon() {
    assert_eq!(percent_decode("%3A"), ":");
    assert_eq!(
        percent_decode("anthropic.claude-3%3A0"),
        "anthropic.claude-3:0"
    );
}

/// `%2E` decodes to a period, and an undecoded id passes unchanged.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_period_and_plain`.
#[test]
fn percent_decode_turns_an_escaped_period_into_a_period_and_leaves_a_plain_id() {
    assert_eq!(percent_decode("a%2Eb"), "a.b");
    assert_eq!(
        percent_decode("anthropic.claude-3-sonnet"),
        "anthropic.claude-3-sonnet"
    );
}

/// A malformed escape is left verbatim.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_malformed_escape_passes_through`.
#[test]
fn percent_decode_leaves_a_malformed_escape_verbatim() {
    assert_eq!(percent_decode("%XY"), "%XY");
    assert_eq!(percent_decode("a%ZZb"), "a%ZZb");
}

/// A trailing `%`, or one with too few bytes after it, passes through.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_percent_decode_trailing_percent_is_safe`.
#[test]
fn percent_decode_passes_a_trailing_percent_through() {
    assert_eq!(percent_decode("abc%"), "abc%");
    assert_eq!(percent_decode("abc%3"), "abc%3");
}

/// A JSON array to a bedrock path is a `ValidationException` 400 carrying the `x-amzn-errortype`
/// field, never a panic or a 500.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_non_object_body_is_400`.
#[test]
fn a_non_object_bedrock_body_is_a_validation_exception_400() {
    let d = no("/model/foo/converse", &json(), b"[1,2]");
    assert_eq!((d.why, d.status), (Decline::NotAnObject, 400));
    let (r, v) = rendered("/model/foo/converse", &json(), b"[1,2]");
    assert_eq!(r.status, 400);
    assert!(
        field(&r, "x-amzn-errortype").is_some(),
        "the bedrock refusal carries x-amzn-errortype: {:?}",
        r.fields
    );
    assert_eq!(v["__type"], "ValidationException", "{v}");
}

/// The URL's model and stream flag win over the body's; every other member survives.
///
/// Ports legacy `crates/busbar-llm/src/unit/tests/arrival.rs::the_url_model_and_stream_flag_win_over_the_body`.
#[test]
fn the_url_model_and_stream_flag_win_over_the_body() {
    let a = ok(
        "/v1beta/models/from-the-url:streamGenerateContent?alt=sse",
        &json(),
        br#"{"model":"from-the-body","stream":false,"x":1}"#,
    );
    assert_eq!(a.model, "from-the-url");
    for v in [
        a.parsed.clone().expect("parsed"),
        busbar_plane_llm::codec::json::parse::<Value>(&a.body).expect("the carried bytes"),
    ] {
        assert_eq!(v.get("model").and_then(Value::as_str), Some("from-the-url"));
        assert_eq!(v.get("stream").and_then(Value::as_bool), Some(true));
        assert_eq!(v.get("x").and_then(Value::as_i64), Some(1));
    }
}

/// A body with no content type is read as JSON.
///
/// Ports legacy `crates/busbar-llm/src/unit/tests/arrival.rs::an_absent_content_type_is_read_as_json`.
#[test]
fn an_absent_content_type_is_read_as_json() {
    let a = ok("/v1/chat/completions", &[], br#"{"model":"m"}"#);
    assert_eq!(a.content_type, "");
    assert!(a.parsed.is_some(), "an empty content type parses");
    assert_eq!(a.model, "m");
}

/// A JSON content type with parameters still takes the JSON arm.
///
/// Ports legacy `crates/busbar-llm/src/unit/tests/arrival.rs::a_json_content_type_with_parameters_still_parses`.
#[test]
fn a_json_content_type_with_parameters_still_parses() {
    let h = head(&[("content-type", "application/json; charset=utf-8")]);
    let a = ok("/v1/chat/completions", &h, br#"{"model":"m"}"#);
    assert!(a.parsed.is_some());
    assert_eq!(a.model, "m");
}

/// The event-stream selector is recognised only as a genuine `alt=sse` pair: not as the value of
/// another parameter, not as a bare `alt`, in any order among other parameters.
///
/// Ports legacy `crates/busbar-llm/src/tests/arrival_tests.rs::test_query_has_alt_sse`.
#[test]
fn the_event_stream_selector_is_only_a_genuine_alt_sse_pair() {
    let streamed = |query: Option<&str>| {
        let target = match query {
            Some(q) => format!("/v1beta/models/gemini-pro:streamGenerateContent?{q}"),
            None => "/v1beta/models/gemini-pro:streamGenerateContent".to_string(),
        };
        let pm = ok(&target, &json(), br#"{"contents":[]}"#)
            .path_model
            .expect("a path model");
        assert!(pm.stream, "{target}");
        !pm.json_array
    };
    for q in ["alt=sse", "key=abc&alt=sse", "alt=sse&key=abc"] {
        assert!(streamed(Some(q)), "{q} asks for events");
    }
    for q in [
        Some("alt=json"),
        Some(""),
        None,
        Some("foo=alt=sse"),
        Some("alt"),
    ] {
        assert!(!streamed(q), "{q:?} is no event-stream selector");
    }
}

/// The recorded request corpus (the codec's frozen request goldens), each body read the way the
/// arrival reads it.
fn fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/tests/proto/golden");
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .expect("the recorded request corpus is readable")
        .filter_map(|e| {
            let path = e.ok()?.path();
            let name = path.file_name()?.to_str()?.to_string();
            (name.starts_with("req_") && name.ends_with(".json"))
                .then(|| (name, std::fs::read(&path).expect("fixture readable")))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(out.len() > 40, "the corpus moved or shrank: {}", out.len());
    out
}

/// For every recorded request, a body-model arrival routes on exactly the model the body names (its
/// `model` string, when non-empty), and refuses a body naming none with the missing-model 400.
///
/// Ports legacy `crates/busbar-llm/src/unit/tests/decode.rs::every_recorded_request_decodes_to_the_live_paths_model`.
#[test]
fn every_recorded_request_arrives_on_the_model_its_body_names() {
    for (name, body) in fixtures() {
        let named = serde_json::from_slice::<Value>(&body)
            .expect("a recorded request is JSON")
            .get("model")
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        for target in [
            "/v1/chat/completions",
            "/v1/messages",
            "/v1/responses",
            "/v2/chat",
        ] {
            match (&named, arrive("POST", target, &json(), &body, &())) {
                (Some(m), Ok(a)) => assert_eq!(&a.model, m, "{name} at {target}"),
                (None, Err(d)) => assert_eq!(
                    (d.why, d.status),
                    (Decline::MissingModel, 400),
                    "{name} at {target}"
                ),
                (want, got) => panic!("{name} at {target}: wanted {want:?}, got {got:?}"),
            }
        }
    }
}
