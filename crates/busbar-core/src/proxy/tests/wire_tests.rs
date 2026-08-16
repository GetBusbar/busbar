// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/proxy/wire.rs`.

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
    let rb = axum::http::Response::builder();
    let (policy, target) =
        built_route_headers(maybe_attach_route_policy_gated(rb, false, None, "claude"));
    assert_eq!(policy, "");
    assert_eq!(target, "");
}

// ── THE ZERO-PLUGIN REFUSAL PATH ────────────────────────────────────────────────────────────────
//
// R-D / R-F: "core with no plugins still compiles and runs, just does nothing" — and a core that
// cannot RENDER a refusal without a dialect linked in does not satisfy that. These two pin the
// dialect-free envelope on the two paths that previously reached for a hardcoded `Protocol::openai`.

/// An ingress name NO registered protocol answers to renders `busbar-api`'s dialect-free envelope
/// rather than borrowing a dialect's writer to phrase the refusal.
///
/// This is the behaviour a zero-protocol build depends on: with no dialects compiled in, EVERY
/// request takes this arm, so if it needed a dialect the build could not refuse anything.
#[test]
fn an_unresolvable_ingress_renders_the_dialect_free_envelope() {
    let resp = super::ingress_error(
        "no-such-protocol",
        StatusCode::BAD_REQUEST,
        "invalid_request_error",
        "no protocol is registered for this request",
    );
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = futures::executor::block_on(async {
        axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap()
    });
    let s = String::from_utf8(body.to_vec()).unwrap();
    // Byte-identical to the ABI's envelope — one statement of the shape, not two.
    assert_eq!(
        s,
        String::from_utf8(busbar_api::protocol::unresolved_ingress_error(
            400,
            "no protocol is registered for this request"
        ))
        .unwrap()
    );
    // And it must still be a body a client can parse.
    let v: serde_json::Value = serde_json::from_str(&s).expect("the refusal must be valid JSON");
    assert_eq!(v["error"]["type"], "invalid_request_error");
}

/// The same property mid-stream: a stream that fails with no resolvable ingress protocol still ends
/// with a parseable SSE error frame. Without this, a zero-protocol build could only hang.
#[test]
fn an_unresolvable_ingress_still_ends_a_stream_with_a_parseable_frame() {
    let bytes = super::mid_stream_error_bytes("no-such-protocol", false, "upstream vanished");
    let s = String::from_utf8(bytes).unwrap();
    assert!(s.starts_with("data: "), "SSE framing preserved: {s}");
    assert!(s.ends_with("\n\n"), "SSE frame terminated: {s}");
    let payload = s.trim_start_matches("data: ").trim_end();
    let v: serde_json::Value =
        serde_json::from_str(payload).expect("the terminal frame must be valid JSON");
    assert_eq!(v["error"]["message"], "upstream vanished");
}
