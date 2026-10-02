// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T3 inbound WEBHOOK RECEIVER tests — Standard-Webhooks signature verification, body parse, and the
//! leniency/wrong-typed contract. Every path is exercised against the always-compiled handler
//! (`openai_responses::webhook`), so these run under default `cargo test -p busbar-llm` regardless of
//! the off-by-default `webhook-receiver` mount.

use super::*;
use axum::http::HeaderMap;

/// A test signing secret in the `whsec_<base64>` shape a real deployment configures.
fn test_secret() -> String {
    // base64 of a fixed 24-byte key — the value is irrelevant, only that decode succeeds.
    let key = b"0123456789abcdef01234567";
    format!(
        "{}{}",
        "whsec_",
        base64::engine::general_purpose::STANDARD.encode(key)
    )
}

/// Compute the CORRECT `webhook-signature` header value for a `(secret, id, timestamp, body)` tuple,
/// so a test can present a genuinely-valid signature. Mirrors the receiver's own signing math (which
/// is the point — a valid signer and the verifier must agree).
fn sign(secret: &str, id: &str, ts: &str, body: &[u8]) -> String {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let key = base64::engine::general_purpose::STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap())
        .unwrap();
    let mut signed = Vec::new();
    signed.extend_from_slice(id.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(ts.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    let mut mac = <Hmac<Sha256>>::new_from_slice(&key).unwrap();
    mac.update(&signed);
    let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!("v1,{sig}")
}

/// Build a HeaderMap carrying the three Standard-Webhooks headers.
fn signed_headers(id: &str, ts: &str, signature: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("webhook-id", id.parse().unwrap());
    h.insert("webhook-timestamp", ts.parse().unwrap());
    h.insert("webhook-signature", signature.parse().unwrap());
    h
}

/// A representative OpenAI Responses `response.completed` webhook body (captured shape).
fn completed_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": "evt_abc123",
        "object": "event",
        "created_at": 1_700_000_900u64,
        "type": "response.completed",
        "data": { "id": "resp_stored_xyz" }
    }))
    .unwrap()
}

// ─────────────────────────────── signature verification ───────────────────────────────

#[test]
fn valid_signature_and_body_is_accepted_and_surfaces_the_correlation_id() {
    let secret = test_secret();
    let (id, ts) = ("msg_1", "1700000900");
    let body = completed_body();
    let headers = signed_headers(id, ts, &sign(&secret, id, ts, &body));

    let event = receive(&secret, &headers, &body).expect("valid webhook must be accepted");
    assert_eq!(
        event.response_id, "resp_stored_xyz",
        "the resp_ correlation id must be surfaced from data.id"
    );
    assert_eq!(event.event_type, "response.completed");
    assert_eq!(event.event_id.as_deref(), Some("evt_abc123"));
    assert_eq!(event.created_at, Some(1_700_000_900));
    assert!(
        event.is_terminal(),
        "response.completed is a terminal event"
    );
}

#[test]
fn a_tampered_body_is_refused_with_signature_mismatch() {
    let secret = test_secret();
    let (id, ts) = ("msg_1", "1700000900");
    let body = completed_body();
    // Sign the ORIGINAL body, then deliver a DIFFERENT body under that signature.
    let headers = signed_headers(id, ts, &sign(&secret, id, ts, &body));
    let tampered = serde_json::to_vec(&serde_json::json!({
        "id": "evt_abc123", "object": "event", "created_at": 1_700_000_900u64,
        "type": "response.completed", "data": { "id": "resp_ATTACKER" }
    }))
    .unwrap();

    assert_eq!(
        receive(&secret, &headers, &tampered),
        Err(WebhookReject::SignatureMismatch),
        "a body that does not match the signature must be refused"
    );
}

#[test]
fn a_wrong_secret_is_refused_with_signature_mismatch() {
    let secret = test_secret();
    let (id, ts) = ("msg_1", "1700000900");
    let body = completed_body();
    // Sign with a DIFFERENT secret than the receiver verifies against.
    let other = format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode(b"a-completely-different-key")
    );
    let headers = signed_headers(id, ts, &sign(&other, id, ts, &body));

    assert_eq!(
        receive(&secret, &headers, &body),
        Err(WebhookReject::SignatureMismatch),
    );
}

#[test]
fn an_unsigned_request_is_refused_for_missing_headers() {
    let secret = test_secret();
    let body = completed_body();
    // No Standard-Webhooks headers at all.
    assert_eq!(
        receive(&secret, &HeaderMap::new(), &body),
        Err(WebhookReject::MissingSignatureHeaders),
    );
    // Partial headers (id + timestamp, no signature) are still "unsigned".
    let mut partial = HeaderMap::new();
    partial.insert("webhook-id", "msg_1".parse().unwrap());
    partial.insert("webhook-timestamp", "1700000900".parse().unwrap());
    assert_eq!(
        receive(&secret, &partial, &body),
        Err(WebhookReject::MissingSignatureHeaders),
    );
}

#[test]
fn a_non_v1_signature_token_does_not_match() {
    let secret = test_secret();
    let (id, ts) = ("msg_1", "1700000900");
    let body = completed_body();
    // Present the CORRECT digest but under a `v2` version tag — an unknown scheme must not pass.
    let v1 = sign(&secret, id, ts, &body);
    let digest = v1.strip_prefix("v1,").unwrap();
    let headers = signed_headers(id, ts, &format!("v2,{digest}"));
    assert_eq!(
        receive(&secret, &headers, &body),
        Err(WebhookReject::SignatureMismatch),
    );
}

#[test]
fn multiple_space_separated_signatures_match_if_any_v1_is_valid() {
    let secret = test_secret();
    let (id, ts) = ("msg_1", "1700000900");
    let body = completed_body();
    let good = sign(&secret, id, ts, &body);
    // A rotation window: a stale signature followed by the valid one.
    let header = format!("v1,c3RhbGVzaWc= {good}");
    let headers = signed_headers(id, ts, &header);
    assert!(receive(&secret, &headers, &body).is_ok());
}

#[test]
fn a_malformed_secret_is_an_operator_500() {
    let (id, ts) = ("msg_1", "1700000900");
    let body = completed_body();
    let headers = signed_headers(id, ts, "v1,anything");
    // No `whsec_` prefix.
    assert_eq!(
        receive("not-a-secret", &headers, &body),
        Err(WebhookReject::MalformedSecret),
    );
    assert_eq!(
        WebhookReject::MalformedSecret.http_status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    );
}

// ─────────────────────────────── body parse / leniency ───────────────────────────────

#[test]
fn body_parses_the_load_bearing_fields() {
    let event = parse_event(&completed_body()).expect("well-formed body must parse");
    assert_eq!(event.response_id, "resp_stored_xyz");
    assert_eq!(event.event_type, "response.completed");
}

#[test]
fn body_tolerates_absent_and_unknown_fields() {
    // No `id`, no `created_at`, plus an UNKNOWN top-level key — all tolerated (leniency contract).
    let body = serde_json::to_vec(&serde_json::json!({
        "type": "response.failed",
        "data": { "id": "resp_1", "status": "failed" },
        "some_future_field": { "nested": true }
    }))
    .unwrap();
    let event = parse_event(&body).expect("absent optionals + unknown keys must be lenient");
    assert_eq!(event.response_id, "resp_1");
    assert_eq!(event.event_id, None);
    assert_eq!(event.created_at, None);
    assert!(event.is_terminal());
}

#[test]
fn body_rejects_present_but_wrong_typed_modeled_fields() {
    // `type` present but not a string.
    let type_wrong =
        serde_json::to_vec(&serde_json::json!({ "type": 5, "data": { "id": "resp_1" } })).unwrap();
    // `type` present but empty.
    let type_empty =
        serde_json::to_vec(&serde_json::json!({ "type": "", "data": { "id": "resp_1" } })).unwrap();
    // `data.id` present but not a string.
    let id_wrong = serde_json::to_vec(
        &serde_json::json!({ "type": "response.completed", "data": { "id": 7 } }),
    )
    .unwrap();
    // `data` present but not an object.
    let data_wrong =
        serde_json::to_vec(&serde_json::json!({ "type": "response.completed", "data": "resp_1" }))
            .unwrap();
    // `created_at` present but not an integer.
    let created_wrong = serde_json::to_vec(&serde_json::json!({
        "type": "response.completed", "created_at": "yesterday", "data": { "id": "resp_1" }
    }))
    .unwrap();
    // `data` absent entirely — no correlation key.
    let no_data = serde_json::to_vec(&serde_json::json!({ "type": "response.completed" })).unwrap();
    // Not a JSON object.
    let not_object = serde_json::to_vec(&serde_json::json!(["response.completed"])).unwrap();

    for (label, body) in [
        ("type wrong-typed", type_wrong),
        ("type empty", type_empty),
        ("data.id wrong-typed", id_wrong),
        ("data non-object", data_wrong),
        ("created_at wrong-typed", created_wrong),
        ("data absent", no_data),
        ("body not object", not_object),
    ] {
        assert_eq!(
            parse_event(&body),
            Err(WebhookReject::MalformedBody),
            "{label} must be refused as a malformed body"
        );
    }
}

#[test]
fn reject_http_statuses_are_honest() {
    use axum::http::StatusCode;
    assert_eq!(
        WebhookReject::MissingSignatureHeaders.http_status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        WebhookReject::MalformedBody.http_status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        WebhookReject::SignatureMismatch.http_status(),
        StatusCode::UNAUTHORIZED
    );
}
