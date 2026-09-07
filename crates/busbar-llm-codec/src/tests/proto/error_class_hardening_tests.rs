// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ERROR A DIALECT REPORTS IS THE ERROR THE BREAKER SEES — carried, never WIDENED.
//!
//! WHY THIS FILE EXISTS. Each of the six readers ends `extract_error` with a PROSE SCAN that can
//! override the parsed provider code with the canonical context-length code. That code is the one
//! signal the breaker treats as "the lane is healthy, fail over WITHOUT penalty", so the scan's
//! conjunctions are a disposition boundary in both directions:
//!
//! * TOO WIDE (an `&&` that becomes an `||`, or a missing status gate) turns a genuine auth,
//!   rate-limit or server fault whose prose merely mentions a token into a no-penalty failover: the
//!   breaker records NO fault, the lane is never benched, and a hard-down credential keeps being
//!   picked and keeps failing.
//! * TOO NARROW (an `||` that becomes an `&&`) drops the real oversized-request signal, so an
//!   oversized request is dispositioned as a plain client error that PENALIZES a healthy lane and
//!   never fails over to a larger-context model.
//!
//! A mutation run over the readers left both halves of those conjunctions alive. They are pinned
//! here, per dialect, in both directions, along with the status gate that confines the scan.
//!
//! SPEC ANCHOR. The error envelopes below are the ones the specifications PINNED BY DIGEST in
//! `testing/llm-conformance/spec-digests.tsv` declare: `anthropic` (digest `d1d189d7…`,
//! `ErrorResponse` — `error.type` / `error.message`), `openai` (digest `5f2358ee…`, `ErrorResponse`
//! — `error.{code,message,type}`, shared by `/chat/completions` and `/responses`), `gemini` (digest
//! `836bf6ea…`, whose errors are `google.rpc.Status` — the shape also carried in
//! `testing/llm-conformance/schemas/google-rpc-status.json` — with an integer `code` and a
//! `status` name), `bedrock` (digest `618bf3a6…`, the modeled exceptions, whose wire form carries
//! `__type` and `message`) and `cohere` (digest `6f64ec87…`, whose per-status error bodies carry
//! `message` and `error_type`).

use super::*;
use http::StatusCode;

/// The canonical code the breaker maps to a no-penalty, fail-over-to-a-bigger-model disposition.
const CONTEXT_LENGTH: &str = busbar_substrate_values::proxy::PROVIDER_CODE_CONTEXT_LENGTH;

fn raw(
    proto: &str,
    status: u16,
    body: &[u8],
) -> busbar_substrate_values::breaker::RawUpstreamError {
    protocol_for(proto)
        .expect("known proto")
        .reader()
        .extract_error(StatusCode::from_u16(status).expect("status"), body)
}

fn is_context_length(proto: &str, status: u16, body: &[u8]) -> bool {
    raw(proto, status, body).provider_code.as_deref() == Some(CONTEXT_LENGTH)
}

/// A GENUINE oversized-request body, on the status the provider actually uses for one, IS the
/// context-length signal — for every dialect. Losing this is a healthy lane penalized and no
/// failover to a larger-context model.
#[test]
fn a_real_oversized_request_body_carries_the_context_length_signal() {
    // anthropic: `prompt is too long`, and the `exceeds the maximum` + token pairing.
    assert!(is_context_length(
        "anthropic",
        400,
        br#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 300000 tokens > 200000 maximum"}}"#,
    ));
    assert!(is_context_length(
        "anthropic",
        400,
        br#"{"type":"error","error":{"type":"invalid_request_error","message":"input exceeds the maximum number of tokens"}}"#,
    ));

    // openai chat: the canonical prose, in the error MESSAGE.
    assert!(is_context_length(
        "openai",
        400,
        br#"{"error":{"message":"This model's maximum context length is 8192 tokens, however you requested 9000 tokens.","type":"invalid_request_error","code":null}}"#,
    ));

    // responses: the same prose, scanned over the body.
    assert!(is_context_length(
        "responses",
        400,
        br#"{"error":{"message":"This model's maximum context length is 8192 tokens.","type":"invalid_request_error","code":null}}"#,
    ));

    // gemini: a google.rpc.Status INVALID_ARGUMENT whose message carries the overflow.
    assert!(is_context_length(
        "gemini",
        400,
        br#"{"error":{"code":400,"message":"The input token count exceeds the maximum number of tokens allowed.","status":"INVALID_ARGUMENT"}}"#,
    ));

    // bedrock: a ValidationException whose message carries the overflow.
    assert!(is_context_length(
        "bedrock",
        400,
        br#"{"__type":"ValidationException","message":"Input is longer than the maximum number of tokens allowed"}"#,
    ));

    // cohere: the v2 free-text phrasing.
    assert!(is_context_length(
        "cohere",
        400,
        br#"{"message":"too many tokens: the request exceeds the maximum context length","error_type":"invalid_request_error"}"#,
    ));
}

/// THE CONJUNCTIONS ARE NOT DISJUNCTIONS. A 400 whose prose mentions a token — or a context — for
/// an unrelated reason must NOT be dispositioned as a context-length failover. Every body below is
/// a real client/auth/quota failure that happens to contain one half of a scan's conjunction; the
/// other half is absent, and the scan must therefore not fire.
#[test]
fn a_body_that_merely_mentions_a_token_is_not_an_oversized_request() {
    let unrelated: &[(&str, &[u8])] = &[
        (
            "anthropic",
            br#"{"type":"error","error":{"type":"authentication_error","message":"Your API token is not valid"}}"#,
        ),
        (
            "anthropic",
            br#"{"type":"error","error":{"type":"invalid_request_error","message":"the context field is not permitted here"}}"#,
        ),
        (
            "openai",
            br#"{"error":{"message":"You have reached the maximum number of tokens allowed per day","type":"insufficient_quota","code":null}}"#,
        ),
        (
            "responses",
            br#"{"error":{"message":"You have reached the maximum number of tokens allowed per day","type":"insufficient_quota","code":null}}"#,
        ),
        (
            "gemini",
            br#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT"}}"#,
        ),
        (
            "bedrock",
            br#"{"__type":"ValidationException","message":"The provided token is malformed"}"#,
        ),
        (
            "bedrock",
            br#"{"__type":"ValidationException","message":"The requested field is missing"}"#,
        ),
        (
            "cohere",
            br#"{"message":"invalid token supplied in the request","error_type":"invalid_request_error"}"#,
        ),
    ];
    for (proto, body) in unrelated {
        assert!(
            !is_context_length(proto, 400, body),
            "{proto}: a body that merely mentions a token/context is not an oversized request — \
             classifying it as one lets a real fault escape the breaker with no penalty",
        );
    }
}

/// THE DISJUNCTIONS ARE NOT CONJUNCTIONS. The scans accept `token` OR `context` beside the
/// co-located phrase — a real provider message carries one of them, not both. Requiring both drops
/// the signal and penalizes a healthy lane.
#[test]
fn one_half_of_the_token_or_context_pair_is_enough() {
    // "token" present, "context" absent.
    assert!(is_context_length(
        "anthropic",
        400,
        br#"{"type":"error","error":{"type":"invalid_request_error","message":"request exceeds the maximum number of tokens for this model"}}"#,
    ));
    // "context" present, "token" absent.
    assert!(is_context_length(
        "anthropic",
        400,
        br#"{"type":"error","error":{"type":"invalid_request_error","message":"request exceeds the maximum context size for this model"}}"#,
    ));
    assert!(is_context_length(
        "bedrock",
        400,
        br#"{"__type":"ValidationException","message":"request exceeds the maximum number of tokens"}"#,
    ));
    assert!(is_context_length(
        "bedrock",
        400,
        br#"{"__type":"ValidationException","message":"request exceeds the maximum context window"}"#,
    ));
    assert!(is_context_length(
        "gemini",
        400,
        br#"{"error":{"code":400,"message":"request exceeds the maximum context window","status":"INVALID_ARGUMENT"}}"#,
    ));
}

/// THE STATUS GATE. The prose scan is confined to the statuses a provider actually uses for an
/// oversized request. A 401, a 429 or a 5xx whose body quotes the request's token count keeps its
/// own disposition — otherwise a dead credential or a throttled lane is laundered into a
/// no-penalty failover and never benched.
#[test]
fn the_context_length_scan_is_confined_to_request_size_statuses() {
    let oversized_prose: &[(&str, &[u8])] = &[
        (
            "anthropic",
            br#"{"type":"error","error":{"type":"rate_limit_error","message":"prompt is too long: 300000 tokens > 200000 maximum"}}"#,
        ),
        (
            "openai",
            br#"{"error":{"message":"This model's maximum context length is 8192 tokens.","type":"rate_limit_error","code":null}}"#,
        ),
        (
            "responses",
            br#"{"error":{"message":"This model's maximum context length is 8192 tokens.","type":"rate_limit_error","code":null}}"#,
        ),
        (
            "gemini",
            br#"{"error":{"code":429,"message":"The input token count exceeds the maximum allowed.","status":"RESOURCE_EXHAUSTED"}}"#,
        ),
        (
            "bedrock",
            br#"{"__type":"ThrottlingException","message":"Input is longer than the maximum number of tokens allowed"}"#,
        ),
        (
            "cohere",
            br#"{"message":"too many tokens: the request exceeds the maximum context length","error_type":"rate_limit_error"}"#,
        ),
    ];
    for (proto, body) in oversized_prose {
        for status in [401u16, 403, 429, 500, 503] {
            assert!(
                !is_context_length(proto, status, body),
                "{proto}: a {status} whose prose mentions the context length must keep its own \
                 disposition — reclassifying it hides the fault from the breaker",
            );
        }
        // …and on the request-size statuses the very same body IS the signal, so the gate is a
        // gate and not a blanket refusal.
        assert!(is_context_length(proto, 400, body), "{proto}: 400");
    }
}

/// THE UPSTREAM'S OWN STATUS AND STRUCTURED TYPE ARE CARRIED VERBATIM. The prose scan may only
/// replace the provider CODE; the HTTP status the upstream answered and the machine-readable type
/// it named are the breaker's other two inputs and must reach it unchanged — a widened or dropped
/// type is a lane dispositioned on less than the upstream said.
#[test]
fn the_upstream_status_and_structured_type_survive_the_scan() {
    let e = raw(
        "anthropic",
        429,
        br#"{"type":"error","error":{"type":"rate_limit_error","message":"prompt is too long: 300000 tokens"}}"#,
    );
    assert_eq!(e.http_status, 429);
    assert_eq!(e.structured_type.as_deref(), Some("rate_limit_error"));

    let e = raw(
        "openai",
        401,
        br#"{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","code":"invalid_api_key"}}"#,
    );
    assert_eq!(e.http_status, 401);
    assert_eq!(e.structured_type.as_deref(), Some("invalid_request_error"));
    assert_eq!(e.provider_code.as_deref(), Some("invalid_api_key"));

    // bedrock names its exception in `__type`, possibly ARN-qualified; only the trailing token is
    // the type, and it must survive.
    let e = raw(
        "bedrock",
        500,
        br#"{"__type":"com.amazon.coral.service#ThrottlingException","message":"slow down"}"#,
    );
    assert_eq!(e.http_status, 500);
    assert_eq!(e.structured_type.as_deref(), Some("ThrottlingException"));

    // gemini's google.rpc.Status names the code as an INTEGER and the class as `status`.
    let e = raw(
        "gemini",
        429,
        br#"{"error":{"code":429,"message":"Resource has been exhausted","status":"RESOURCE_EXHAUSTED"}}"#,
    );
    assert_eq!(e.http_status, 429);
    assert_eq!(e.structured_type.as_deref(), Some("RESOURCE_EXHAUSTED"));
    assert_eq!(
        e.provider_code.as_deref(),
        Some("429"),
        "a numeric google.rpc code is carried as the code it is, not dropped for the status name"
    );

    // cohere names its class in `error_type`.
    let e = raw(
        "cohere",
        403,
        br#"{"message":"forbidden","error_type":"permission_error"}"#,
    );
    assert_eq!(e.http_status, 403);
    assert_eq!(e.structured_type.as_deref(), Some("permission_error"));
}

/// AN UNPARSEABLE ERROR BODY IS STILL AN ERROR AT THE STATUS THE UPSTREAM ANSWERED. A body that is
/// not JSON at all (an HTML gateway page, a truncated response) must not panic, and must not
/// silently become a different class: the status carries the disposition on its own.
#[test]
fn an_unparseable_error_body_keeps_the_upstream_status() {
    for proto in [
        "anthropic",
        "openai",
        "responses",
        "gemini",
        "bedrock",
        "cohere",
    ] {
        for status in [400u16, 401, 429, 500] {
            let e = raw(proto, status, b"<html><body>502 Bad Gateway</body></html>");
            assert_eq!(e.http_status, status, "{proto}");
            assert!(
                e.provider_code.as_deref() != Some(CONTEXT_LENGTH),
                "{proto}: a gateway page is not an oversized request"
            );
        }
    }
}

/// A MALFORMED RESPONSE BODY FAILS AS AN IR-PARSE CLIENT ERROR, AND SAYS SO. The parse signal is
/// what distinguishes "busbar could not read this body" from an upstream-attributed fault; dropped,
/// the failure is indistinguishable from a bare client error and the reason is unanswerable.
#[test]
fn a_body_the_reader_cannot_parse_reports_the_ir_parse_signal() {
    for proto in [
        "anthropic",
        "openai",
        "responses",
        "gemini",
        "bedrock",
        "cohere",
    ] {
        let p = protocol_for(proto).expect("known proto");
        let reader = p.reader();
        // A JSON scalar where an object is required.
        let err = reader
            .read_response(&serde_json::json!("not an object"))
            .expect_err("a scalar body is not a response");
        assert_eq!(err.class, StatusClass::ClientError, "{proto}");
        assert_eq!(
            err.provider_signal.as_deref(),
            Some(SIGNAL_IR_PARSE),
            "{proto}: an unreadable body must name the parse signal"
        );
        assert_eq!(
            err.retry_after, None,
            "{proto}: a parse failure is not retryable-after"
        );

        let err = reader
            .read_request(&serde_json::json!(42))
            .expect_err("a scalar body is not a request");
        assert_eq!(err.class, StatusClass::ClientError, "{proto}");
        assert_eq!(
            err.provider_signal.as_deref(),
            Some(SIGNAL_IR_PARSE),
            "{proto}: an unreadable request must name the parse signal"
        );
    }
}

/// EVERY structurally-invalid RESPONSE shape names the parse signal, not just a non-object body.
/// A body whose `role` is not the assistant's, and one with no `content` member at all, are both
/// bodies busbar could not read — and each is reported as such rather than as an anonymous client
/// error whose cause cannot be answered from the record.
#[test]
fn each_unreadable_response_shape_names_the_parse_signal() {
    let p = protocol_for("anthropic").expect("known proto");
    let reader = p.reader();

    // A `role` the pinned Anthropic `Message` never carries on a response.
    let err = reader
        .read_response(&serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "user",
            "content": [{"type": "text", "text": "hi"}],
        }))
        .expect_err("a non-assistant role is not a readable response");
    assert_eq!(err.class, StatusClass::ClientError);
    assert_eq!(err.provider_signal.as_deref(), Some(SIGNAL_IR_PARSE));

    // `content` is required by the same schema; absent, the body is unreadable.
    let err = reader
        .read_response(&serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
        }))
        .expect_err("a response with no content member is not readable");
    assert_eq!(err.class, StatusClass::ClientError);
    assert_eq!(err.provider_signal.as_deref(), Some(SIGNAL_IR_PARSE));
}

/// A MID-STREAM ERROR CARRIES THE UPSTREAM'S OWN TYPE AND CLASS. The pinned Anthropic document
/// (digest `d1d189d7…`) declares an `error` event inside `MessageStreamEvent`, carrying the same
/// `error.type` vocabulary as a non-stream `ErrorResponse`. That type is the breaker's attribution:
/// an `overloaded_error` or `rate_limit_error` mid-stream is a TRANSIENT UPSTREAM fault, and
/// flattening it into a generic client fault means the breaker records nothing, never benches the
/// lane, and keeps routing to an upstream that is failing.
#[test]
fn a_mid_stream_error_keeps_the_upstream_type_and_class() {
    let p = protocol_for("anthropic").expect("known proto");
    let reader = p.reader();
    let cases: &[(&str, StatusClass)] = &[
        ("overloaded_error", StatusClass::Overloaded),
        ("rate_limit_error", StatusClass::RateLimit),
        ("api_error", StatusClass::ServerError),
        ("authentication_error", StatusClass::Auth),
        ("billing_error", StatusClass::Billing),
        ("invalid_request_error", StatusClass::ClientError),
    ];
    for (error_type, class) in cases {
        let ev = reader
            .read_response_event(
                "error",
                &serde_json::json!({
                    "type": "error",
                    "error": {"type": error_type, "message": "upstream said so"},
                }),
            )
            .expect("a mid-stream error event is an IR error event");
        match ev {
            ir::IrStreamEvent::Error(err) => {
                assert_eq!(
                    err.class, *class,
                    "{error_type}: the upstream's own disposition must reach the breaker"
                );
                assert_eq!(
                    err.provider_signal.as_deref(),
                    Some(*error_type),
                    "{error_type}: the upstream's type is the attribution and must be carried"
                );
                assert_eq!(err.retry_after, None, "{error_type}");
            }
            other => panic!("expected an IR error event, got {other:?}"),
        }
    }
}
