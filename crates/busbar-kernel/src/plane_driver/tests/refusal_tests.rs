// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S DIALECT REFUSAL, pinned to the byte at its home: an ingress name that resolves to no
//! protocol is answered in the neutral envelope — the status as given, `application/json` as the
//! ONLY header, and the body `{"error":{"message":…,"type":…}}` exactly as 1.5.5 wrote it — and the
//! kind-neutral auth classification of an unknown protocol is 1.5.5's (401, `authentication_error`).

use http_body_util::BodyExt as _;

use super::{agnostic_error_envelope, ingress_error};

#[tokio::test]
async fn an_unresolved_ingress_is_refused_in_the_neutral_envelope_byte_for_byte() {
    let resp = ingress_error(
        "no-such-protocol",
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        busbar_contract::protocol::KIND_OVERLOADED,
        "everything is on fire",
    );
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().len(), 1, "{:?}", resp.headers());
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.as_bytes()),
        Some(&b"application/json"[..])
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &bytes[..],
        &br#"{"error":{"message":"everything is on fire","type":"overloaded"}}"#[..]
    );
}

#[test]
fn the_neutral_envelope_states_the_kind_and_message_verbatim() {
    assert_eq!(
        agnostic_error_envelope("rate_limit_error", "slow down"),
        serde_json::json!({ "error": { "message": "slow down", "type": "rate_limit_error" } })
    );
}

#[test]
fn an_unknown_protocol_is_classified_401_authentication_error() {
    let (status, kind) = crate::auth::auth_failure_status_and_kind("no-such-protocol");
    assert_eq!(status, http::StatusCode::UNAUTHORIZED);
    assert_eq!(kind, "authentication_error");
}
