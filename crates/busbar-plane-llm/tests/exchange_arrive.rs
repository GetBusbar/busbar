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

/// A REFUSAL A DIALECT READ IS COUNTED (ARCHITECT RULING U11 Q3 2026-10-06): a path-model URL that
/// names no model and action, or an action its dialect does not serve (`:countTokens`), is refused
/// 404 and counted, as 1.5.5 counted it through `finish_rejected` (v1.5.5
/// `crates/busbar/src/ingress/mod.rs:843`, `:864`, `:913`, `:931`); a path no dialect claims and a
/// verb a dialect path does not take are refused uncounted, as is every other refusal by this rule.
#[test]
fn a_refusal_a_dialect_read_is_counted_and_one_none_read_is_not() {
    for target in [
        "/v1beta/models/gemini-pro:countTokens",
        "/v1beta/models/gemini-pro:fly",
    ] {
        let d = no(target, &json(), b"{}");
        assert_eq!((d.why, d.status), (Decline::PathNotFound, 404), "{target}");
        assert!(d.counted(), "{target}: its dialect read it");
    }
    let d = no("/nowhere", &json(), b"{}");
    assert_eq!((d.why, d.status), (Decline::NoResource, 404));
    assert!(!d.counted(), "no dialect read an unknown path");
    let d = arrive("GET", "/v1/chat/completions", &json(), b"", &()).expect_err("refused");
    assert_eq!((d.why, d.status), (Decline::MethodNotAllowed, 405));
    assert!(
        !d.counted(),
        "no dialect read a verb its path does not take"
    );
    for why in [
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
    ] {
        let d = Declined {
            why,
            status: 404,
            envelope: "",
            kind: "not_found_error",
            message: "x".into(),
        };
        assert_eq!(d.counted(), why == Decline::PathNotFound, "{why:?}");
    }
}
