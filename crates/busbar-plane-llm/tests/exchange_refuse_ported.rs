// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The refusal cases the retired engine crate's tests pinned, ported onto the plane's one renderer:
//! a dialect reader's rejection as the caller reads it, the request id one dialect's error carries
//! twice, and the missing-model refusal in each dialect's own error shape against 1.5.5's recorded
//! envelope. Each test cites the legacy test it ports.

use std::path::{Path, PathBuf};

use busbar_contract::codec::IngressReject;
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::KIND_INVALID_REQUEST;
use busbar_plane_llm::exchange::arrive::{arrive, Decline};
use busbar_plane_llm::exchange::attempt::ingress_reject;
use busbar_plane_llm::exchange::refuse::{answered, declined, render, Rendered};
use serde_json::Value;

/// The host's entropy, so a dialect that mints a request id mints one.
fn entropy() {
    busbar_contract::codec::install_entropy_source(|out| getrandom::fill(out).is_ok());
}

fn body(r: &Rendered) -> Value {
    serde_json::from_slice(&r.body).expect("a refusal body is JSON")
}

fn field<'a>(r: &'a Rendered, name: &str) -> Option<&'a [u8]> {
    r.fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
}

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

/// A reader's sub-operation rejection is a 404 naming the operation by its published name (never
/// the type's debug shape) and the model.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_reject_response_tests.rs::unsupported_sub_op_rejects_with_404_naming_op_and_model`.
#[test]
fn an_unsupported_sub_operation_is_a_404_naming_the_operation_and_the_model() {
    entropy();
    let a = ingress_reject(
        "openai",
        &IngressReject::UnsupportedSubOp {
            op: OpVerb::IMAGE,
            model: "dall-e-2".into(),
        },
    );
    let r = answered(&a);
    assert_eq!(r.status, 404);
    let v = body(&r);
    let detail = v
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        detail.contains("image") && detail.contains("dall-e-2"),
        "{detail}"
    );
    assert!(
        !detail.contains("Verb") && !detail.contains("OpShape") && !detail.contains("Invoke"),
        "the published name, never the debug shape: {detail}"
    );
}

/// A reader's bad-request rejection keeps the generic 400 sentence.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_reject_response_tests.rs::bad_request_reject_keeps_the_unchanged_generic_400`.
#[test]
fn a_bad_request_rejection_is_the_generic_400() {
    entropy();
    let r = answered(&ingress_reject(
        "openai",
        &IngressReject::BadRequest("x".into()),
    ));
    assert_eq!(r.status, 400);
    assert_eq!(
        body(&r).pointer("/error/message").and_then(Value::as_str),
        Some("We could not process the content of your request.")
    );
}

/// An anthropic error's `request-id` field carries the anthropic `req_` shape and equals the body's
/// `request_id`; no other dialect's error carries that field.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_anthropic_ingress_error_request_id_header_matches_body`.
#[test]
fn an_anthropic_errors_request_id_field_equals_its_body() {
    entropy();
    let r = render("anthropic", 400, KIND_INVALID_REQUEST, "bad json", 0);
    let id = std::str::from_utf8(field(&r, "request-id").expect("a request-id field"))
        .expect("text")
        .to_string();
    assert!(id.starts_with("req_"), "{id}");
    assert_eq!(body(&r)["request_id"].as_str(), Some(id.as_str()));
    for d in SIX.iter().filter(|d| **d != "anthropic") {
        let r = render(d, 400, KIND_INVALID_REQUEST, "bad json", 0);
        assert!(field(&r, "request-id").is_none(), "{d}: {:?}", r.fields);
    }
}

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

/// The sentence 1.5.5 answered a body-model request naming no model with.
const MISSING_MODEL: &str = "Missing required parameter: 'model'.";

/// The sentence of the recorded malformed-body refusal, whose envelope is the same 400 shape.
const MALFORMED: &str = "We could not parse the JSON body of your request.";

/// Where a dialect's arrival names its model in the body.
fn body_model_target(d: &str) -> Option<&'static str> {
    match d {
        "anthropic" => Some("/v1/messages"),
        "openai" => Some("/v1/chat/completions"),
        "responses" => Some("/v1/responses"),
        "cohere" => Some("/v2/chat"),
        _ => None,
    }
}

/// THE MISSING-MODEL REFUSAL, IN EACH DIALECT'S OWN SHAPE: status 400, the dialect's recorded 400
/// envelope (1.5.5's malformed-body cell of the same dialect, its sentence the missing-model one),
/// and the same head field names. A body-model dialect reaches it through its own arrival; the two
/// URL-model dialects, whose URL always names a model, through the renderer the arrival uses.
///
/// Ports legacy `crates/busbar-llm/src/unit/tests/decode.rs::the_missing_model_refusal_carries_the_live_arms_bytes`.
#[test]
fn the_missing_model_refusal_reads_each_dialects_recorded_400() {
    entropy();
    for d in SIX {
        let r = match body_model_target(d) {
            Some(target) => {
                let h: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
                let refused = arrive("POST", target, h, br#"{"messages":[]}"#, &())
                    .expect_err("no model is refused");
                assert_eq!(
                    (refused.why, refused.status),
                    (Decline::MissingModel, 400),
                    "{d}"
                );
                declined(&refused)
            }
            None => render(d, 400, KIND_INVALID_REQUEST, MISSING_MODEL, 0),
        };
        let cell = format!("llm__{d}__{d}__request__malformed.json");
        let text = std::fs::read_to_string(golden().join(&cell)).expect("the recording");
        let want: Value =
            serde_json::from_str(&text.replace(MALFORMED, MISSING_MODEL)).expect("JSON");
        assert_eq!(
            u64::from(r.status),
            want["status"].as_u64().expect("status"),
            "{d}"
        );
        let mut have = body(&r);
        if let Some(id) = have.get_mut("request_id") {
            *id = Value::String("<ID>".into());
        }
        assert_eq!(have, want["body"]["json"], "{d}: body");
        let mut names: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
        let mut rec: Vec<&str> = want["headers"]
            .as_object()
            .expect("headers")
            .keys()
            .map(String::as_str)
            .filter(|n| *n != "content-length")
            .collect();
        names.sort_unstable();
        rec.sort_unstable();
        assert_eq!(names, rec, "{d}: head field names");
    }
}
