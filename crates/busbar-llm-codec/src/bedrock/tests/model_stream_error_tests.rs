// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MODEL-SIDE FAILURE KEEPS THE STATUS THE MODEL RETURNED.
//!
//! The pinned Bedrock service model (botocore @ e5c81226,
//! `bedrock-runtime/2023-09-30/service-2.json`) shapes `ModelStreamErrorException` with THREE
//! members:
//!
//!   message             NonBlankString
//!   originalStatusCode  StatusCode          "The original status code."   (integer, 100..599)
//!   originalMessage     NonBlankString      "The original message."
//!
//! The exception is Bedrock's envelope for a failure the MODEL raised mid-stream, and
//! `originalStatusCode` is the status the model itself returned. This reader discarded both
//! `original*` members and pinned the class to `ServerError` for every one.
//!
//! `ServerError` is the breaker's PENALIZE-THE-LANE disposition. So a model-side 429 — the
//! throttle Bedrock relays verbatim under this envelope — was recorded as a lane fault instead of
//! a rate limit: the breaker penalized (and eventually opened on) a lane that was perfectly
//! healthy, and the client never saw the 429 or the model's own sentence. A model-side 400
//! (`ValidationException` relayed through the stream) was likewise charged to the lane rather than
//! returned to the caller who caused it.

use super::*;

fn error_of(data: serde_json::Value) -> busbar_substrate_values::proto::IrError {
    let mut state = crate::ir::StreamDecodeState::default();
    BedrockReader
        .read_response_events("", &data, &mut state)
        .into_iter()
        .find_map(|e| match e {
            IrStreamEvent::Error(err) => Some(err),
            _ => None,
        })
        .expect("a modeled exception event must surface an Error")
}

/// The status the model returned decides the class, through the SAME universal status ladder every
/// other upstream error is classified by.
#[test]
fn the_models_own_status_decides_the_class() {
    let cases = [
        (429, StatusClass::RateLimit),
        (400, StatusClass::ClientError),
        (401, StatusClass::Auth),
        (408, StatusClass::Timeout),
        (500, StatusClass::ServerError),
        (503, StatusClass::ServerError),
    ];
    for (status, expected) in cases {
        let err = error_of(serde_json::json!({
            "type": "modelStreamErrorException",
            "message": "An error occurred while streaming the response. Retry your request.",
            "originalStatusCode": status,
            "originalMessage": "the model said so"
        }));
        assert_eq!(
            err.class, expected,
            "a model-side {status} must classify as {expected:?}, not as a lane fault"
        );
        assert_eq!(
            err.detail.http_status,
            Some(status),
            "the status the model reported must reach the client verbatim"
        );
        assert_eq!(
            err.detail.message.as_deref(),
            Some("the model said so"),
            "the model's OWN sentence is the one a caller needs, not the envelope's boilerplate"
        );
        assert_eq!(
            err.detail.status_name.as_deref(),
            Some("ModelStreamErrorException"),
            "the exception the upstream named is still carried verbatim"
        );
    }
}

/// With no `originalStatusCode` the answer is exactly what it was: the envelope's own class.
#[test]
fn without_an_original_status_the_envelope_class_is_unchanged() {
    let err = error_of(serde_json::json!({
        "type": "modelStreamErrorException",
        "message": "An error occurred while streaming the response."
    }));
    assert_eq!(err.class, StatusClass::ServerError);
    assert_eq!(err.detail.http_status, None);
    assert_eq!(
        err.detail.message.as_deref(),
        Some("An error occurred while streaming the response.")
    );
}

/// A status outside the range the shape declares (`min: 100, max: 599`) is not a status at all —
/// it is ignored rather than classified, so a hostile frame cannot pick the breaker's disposition
/// with an out-of-range number.
#[test]
fn an_out_of_range_original_status_is_ignored() {
    for bogus in [0, 99, 600, 100_000] {
        let err = error_of(serde_json::json!({
            "type": "modelStreamErrorException",
            "message": "boom",
            "originalStatusCode": bogus
        }));
        assert_eq!(
            err.class,
            StatusClass::ServerError,
            "an out-of-range {bogus} must not steer the class"
        );
        assert_eq!(err.detail.http_status, None);
    }
}

/// The other four modeled stream exceptions are untouched — they carry no `original*` members and
/// classify exactly as they did.
#[test]
fn the_other_stream_exceptions_are_unchanged() {
    for (evt, expected) in [
        ("throttlingException", StatusClass::RateLimit),
        ("validationException", StatusClass::ClientError),
        ("serviceUnavailableException", StatusClass::Overloaded),
        ("internalServerException", StatusClass::ServerError),
    ] {
        let err = error_of(serde_json::json!({ "type": evt, "message": "m" }));
        assert_eq!(err.class, expected, "{evt}");
        assert_eq!(err.detail.http_status, None, "{evt}");
        // ... and a member the service model does not declare on THIS shape cannot steer it: a
        // crafted `originalStatusCode` must not flip a throttle off RateLimit.
        let crafted =
            error_of(serde_json::json!({ "type": evt, "message": "m", "originalStatusCode": 200 }));
        assert_eq!(
            crafted.class, expected,
            "{evt} (crafted originalStatusCode)"
        );
        assert_eq!(crafted.detail.http_status, None, "{evt}");
    }
}
