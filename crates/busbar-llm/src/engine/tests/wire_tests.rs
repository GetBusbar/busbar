// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/proxy/wire.rs`.

use super::*;

/// Read back both `x-busbar-route-*` headers from a built response (empty strings when absent),
/// as a `(policy, target)` pair, so every case below can assert on a plain tuple.
fn built_route_headers(rb: axum::http::response::Builder) -> (String, String) {
    let resp = rb.body(axum::body::Body::empty()).unwrap();
    let get = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    (get(HDR_ROUTE_POLICY), get(HDR_ROUTE_TARGET))
}

/// The OUTER gate: without it, `maybe_attach_route_policy` fires the headers unconditionally
/// whenever a non-default policy chose the lane (`policy_name == Some`) — no config toggle at
/// all. Even with a policy name present, `enabled == false` must suppress BOTH headers.
#[test]
fn route_policy_headers_suppressed_when_outer_gate_disabled_even_with_a_policy_name() {
    crate::testkit::install_test_seams();
    let rb = axum::http::Response::builder();
    let (policy, target) = built_route_headers(maybe_attach_route_policy_gated(
        rb,
        false,
        Some("cheapest"),
        "claude",
    ));
    assert_eq!(
        policy, "",
        "route-policy header must be absent when the outer gate is off"
    );
    assert_eq!(
        target, "",
        "route-target header must be absent when the outer gate is off"
    );
}

/// The INNER gate is independent of the outer one: even with the outer gate ON, a default
/// (`policy_name == None`) routing decision attaches nothing — the zero-cost SWRR path stays
/// header-free regardless of the operator's opt-in.
#[test]
fn route_policy_headers_absent_for_a_default_policy_even_when_outer_gate_enabled() {
    crate::testkit::install_test_seams();
    let rb = axum::http::Response::builder();
    let (policy, target) =
        built_route_headers(maybe_attach_route_policy_gated(rb, true, None, "claude"));
    assert_eq!(
        policy, "",
        "no policy name -> no header, regardless of the outer gate"
    );
    assert_eq!(
        target, "",
        "no policy name -> no header, regardless of the outer gate"
    );
}

/// BOTH gates open (opted in + a non-default policy fired) is the only combination that
/// emits the pair, and it carries the exact policy name / target model passed in.
#[test]
fn route_policy_headers_present_only_when_both_gates_open() {
    crate::testkit::install_test_seams();
    let rb = axum::http::Response::builder();
    let (policy, target) = built_route_headers(maybe_attach_route_policy_gated(
        rb,
        true,
        Some("cheapest"),
        "claude",
    ));
    assert_eq!(policy, "cheapest");
    assert_eq!(target, "claude");
}

/// The FOURTH combination (outer off, inner off) is also silent — completing the 2x2 matrix so no
/// combination is left unpinned.
#[test]
fn route_policy_headers_absent_when_both_gates_closed() {
    crate::testkit::install_test_seams();
    let rb = axum::http::Response::builder();
    let (policy, target) =
        built_route_headers(maybe_attach_route_policy_gated(rb, false, None, "claude"));
    assert_eq!(policy, "");
    assert_eq!(target, "");
}

// ══ THE UNRESOLVED-INGRESS ERROR SHAPE IS CORE'S OWN, NOT A DIALECT'S ═════════════════════════════
//
// `ingress_error`/`mid_stream_error_bytes` used to resolve an unknown ingress name to
// `crate::proto_codec::PROTO_RESPONSES` and shape the error with THAT dialect's writer. Every LLM dialect is a
// droppable plugin (`busbar-llm`) now, so there is no dialect core can promise is linked, and the
// fallback became core's own (`agnostic_error_envelope`/`agnostic_stream_error_frame`).
//
// WHAT MAKES THESE DISCRIMINATING rather than decorative: the Responses writer REWRITES the `kind`
// onto the OpenAI-family error vocabulary — `overloaded` becomes `server_error`, which that
// vocabulary has instead. Core's envelope states the agnostic kind VERBATIM. So `type == "overloaded"`
// FAILS on the old `responses` fallback (it emitted `server_error`) and PASSES on core's own shape.

/// An ingress name that resolves to no protocol gets core's own envelope, agnostic `kind` verbatim,
/// and no dialect response headers.
#[tokio::test]
async fn unknown_ingress_error_envelope_is_core_s_own_and_names_no_dialect() {
    crate::testkit::install_test_seams();
    let resp = ingress_error(
        "no-such-protocol",
        StatusCode::SERVICE_UNAVAILABLE,
        crate::engine::KIND_OVERLOADED,
        "everything is on fire",
    );
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        resp.headers().get("x-amzn-requestid").is_none(),
        "an unresolved ingress must not carry a dialect's error headers"
    );
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON envelope");
    assert_eq!(
        v["error"]["type"], crate::engine::KIND_OVERLOADED,
        "core's envelope states the agnostic kind verbatim; the old `responses` fallback rewrote it \
         to `server_error`"
    );
    assert_eq!(v["error"]["message"], "everything is on fire");
}

/// The streaming half: an unknown ingress gets a bare `data:` frame carrying core's envelope — no
/// `event:` line (some dialects' shape, not others') and no dialect vocabulary in `type`.
#[test]
fn unknown_ingress_mid_stream_error_is_a_bare_data_frame_from_core() {
    crate::testkit::install_test_seams();
    let bytes = mid_stream_error_bytes("no-such-protocol", false, "upstream vanished");
    let s = String::from_utf8(bytes).expect("utf8 frame");
    assert!(
        s.starts_with("data: ") && s.ends_with("\n\n"),
        "expected a bare SSE data frame, got: {s}"
    );
    assert!(
        !s.contains("event:"),
        "core's dialect-free frame must not claim a dialect's `event:` shape: {s}"
    );
    let payload = s
        .trim_start_matches("data: ")
        .trim_end_matches("\n\n")
        .to_string();
    let v: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON");
    assert_eq!(v["error"]["type"], crate::engine::KIND_API_ERROR);
    assert_eq!(v["error"]["message"], "upstream vanished");
}
