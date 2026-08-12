// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO HTTP-EDGE FACTS BUSBAR OWNS ON THE RECEIVING PLANE: the request's media type, and the
//! `A2A-Version` the caller asked to be spoken.
//!
//! ## Why these two are busbar's and not the fronted agent's
//!
//! busbar is content-blind on this plane: it relays the caller's envelope to the backend agent
//! verbatim, and the backend's opinion is what comes back. That is the right posture for `params`,
//! for `method`, and for everything else inside the JSON-RPC body. It is the WRONG posture for the
//! HTTP request line, because busbar is the server the client connected to — busbar terminated the
//! TLS, busbar read the headers, and a caller who asks for a protocol version busbar's endpoint does
//! not speak is owed that answer from busbar rather than from whichever agent happened to be
//! selected. Relaying a request busbar cannot honour and forwarding the backend's happy answer tells
//! the caller its version was accepted when nothing accepted it.
//!
//! Measured against the official A2A TCK at
//! `5996b79f9cefa6fc390980e383e358a66fb9e49e`, the two gaps read:
//!
//! ```text
//! VER-SERVER-002   Expected VersionNotSupportedError for A2A-Version: 99.0
//! JSONRPC-SSE-002  Server MUST return VersionNotSupportedError (-32009) for unsupported
//!                  A2A-Version, but processed the request normally
//! JSONRPC-SSE-002  Error code mismatch: expected ContentTypeNotSupportedError (-32005),
//!                  got ParseError (-32700)
//! ```
//!
//! ## The version set is `0.3` and `1.0`, and the code is what says so
//!
//! Both are claimed because both are already READ. `ingress::shape_of` recognises the v0.3 streaming
//! spelling (`message/stream`, `tasks/resubscribe`) and the v1.0 one (`SendStreamingMessage`,
//! `SubscribeToTask`); `relay` reads a bare v0.3 `result` and a wrapped v1.0 `{"task": …}`; `idmap`
//! rewrites `id`, `taskId` and v1.0's `task_id`. A version this plane demonstrably handles is a
//! version it may claim, and a version nothing in the tree reads is one it may not.
//!
//! An ABSENT or EMPTY header is `0.3` — A2A's own default for a caller that names no version — and is
//! therefore admitted rather than refused. The TCK asserts that separately as `VER-SERVER-003`, and
//! the case is repeated here so a future tightening of this gate cannot pass this file.

use super::relay_harness::*;

/// POST the standard envelope to the agent endpoint under EXACTLY the headers a case varies, and
/// read the status and the parsed body.
///
/// `content_type` and `version` are `Option` rather than defaulted, because "the header is absent"
/// is a case under test on both axes and a helper that always sent one could not express it.
async fn post_with(
    h: &Harness,
    content_type: Option<&str>,
    version: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/planner", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .body(serde_json::to_vec(&envelope()).expect("serialise"));
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    if let Some(v) = version {
        req = req.header("A2A-Version", v);
    }
    let resp = req.send().await.expect("the call completes");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

/// The `error.code` of a JSON-RPC error body, or `None` when the answer is not one.
fn error_code(body: &serde_json::Value) -> Option<i64> {
    body.pointer("/error/code")
        .and_then(serde_json::Value::as_i64)
}

/// The `google.rpc.ErrorInfo` reason A2A §5.4 binds to the error, dug out of the ProtoJSON `data`
/// array. Read rather than assumed: a code with the wrong reason is a body a conformant client
/// mis-classifies, and the array shape is exactly what `rpcerror` had to be fixed to produce once.
fn error_reason(body: &serde_json::Value) -> Option<String> {
    body.pointer("/error/data")?
        .as_array()?
        .iter()
        .find_map(|d| d.get("reason").and_then(serde_json::Value::as_str))
        .map(str::to_string)
}

/// How many times the relay reached for the backend. Zero is the assertion that matters on every
/// refusal here: a request busbar will not honour must not open a task, spend the caller's budget or
/// cause busbar's own credential to be leased for a hop.
fn hops(h: &Harness) -> usize {
    h.log.lock().expect("the log").len()
}

// ══ THE VERSION HEADER ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn a_version_this_endpoint_does_not_speak_is_refused_with_minus_32009() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = post_with(&h, Some("application/json"), Some("99.0")).await;
    assert_eq!(
        error_code(&body),
        Some(-32009),
        "an unsupported A2A-Version owes VersionNotSupportedError: {body}"
    );
    assert_eq!(
        error_reason(&body).as_deref(),
        Some("VERSION_NOT_SUPPORTED")
    );
    assert_eq!(status, 400, "A2A §5.4 binds -32009 to HTTP 400");
    assert_eq!(
        hops(&h),
        0,
        "a request refused at the wire owes no backend hop"
    );
}

#[tokio::test]
async fn the_two_versions_this_plane_reads_are_both_admitted() {
    for version in ["1.0", "0.3", "1.0.7", "0.3.0"] {
        let h = harness(Outcome::Answers(200, backend_ok()), false).await;
        let (status, body) = post_with(&h, Some("application/json"), Some(version)).await;
        assert_eq!(
            error_code(&body),
            None,
            "A2A-Version {version} must be admitted, got {body}"
        );
        assert_eq!(status, 200, "A2A-Version {version}");
        assert_eq!(hops(&h), 1, "A2A-Version {version} must reach the backend");
    }
}

#[tokio::test]
async fn an_absent_or_empty_version_is_the_specifications_default_and_is_admitted() {
    // A2A's own rule: a caller that names no version means 0.3. Refusing here would break every
    // client written before the header existed, and it is what the TCK's VER-SERVER-003 asserts.
    for version in [None, Some("")] {
        let h = harness(Outcome::Answers(200, backend_ok()), false).await;
        let (status, body) = post_with(&h, Some("application/json"), version).await;
        assert_eq!(
            error_code(&body),
            None,
            "A2A-Version {version:?} must be admitted, got {body}"
        );
        assert_eq!(status, 200, "A2A-Version {version:?}");
        assert_eq!(
            hops(&h),
            1,
            "A2A-Version {version:?} must reach the backend"
        );
    }
}

// ══ THE MEDIA TYPE ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn a_media_type_this_endpoint_does_not_accept_is_refused_with_minus_32005() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = post_with(&h, Some("text/plain"), Some("1.0")).await;
    assert_eq!(
        error_code(&body),
        Some(-32005),
        "a non-JSON media type owes ContentTypeNotSupportedError, not ParseError: {body}"
    );
    assert_eq!(
        error_reason(&body).as_deref(),
        Some("CONTENT_TYPE_NOT_SUPPORTED")
    );
    assert_eq!(status, 415, "A2A §5.4 binds -32005 to HTTP 415");
    assert_eq!(
        hops(&h),
        0,
        "a request refused at the wire owes no backend hop"
    );
}

#[tokio::test]
async fn the_media_type_is_read_as_a_media_type_and_not_as_a_string() {
    // A charset parameter does not change the media type, and neither does the case of the type.
    // A gate that compared the whole header value would refuse both of these — which is a working
    // client refused by a check that was supposed to catch a broken one.
    // `application/a2a+json` is in this list because the FIRST draft of the gate refused it, and
    // refusing it would have refused the media type A2A section 11.1 says SHOULD be used — and with
    // it every call the independent battery in `testing/a2a-harness` makes, since `target.py` sets
    // exactly that header on all of them. A gate that turns the suite next door red is not a gate,
    // it is a regression with a specification citation.
    for ct in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON",
        "application/json;charset=UTF-8",
        "application/a2a+json",
        "application/a2a+json; charset=utf-8",
    ] {
        let h = harness(Outcome::Answers(200, backend_ok()), false).await;
        let (status, body) = post_with(&h, Some(ct), Some("1.0")).await;
        assert_eq!(
            error_code(&body),
            None,
            "content-type {ct:?} must be admitted, got {body}"
        );
        assert_eq!(status, 200, "content-type {ct:?}");
        assert_eq!(hops(&h), 1, "content-type {ct:?} must reach the backend");
    }
}

#[tokio::test]
async fn an_absent_media_type_is_not_refused() {
    // Deliberately LENIENT, and stated rather than left to be inferred: the specification requires a
    // conformant client to send `application/json`, but a request that names no media type has not
    // named a WRONG one, and refusing it would turn this gate into a new way to break callers that
    // work today. The body still has to parse as JSON, which is the check that was already here.
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = post_with(&h, None, Some("1.0")).await;
    assert_eq!(error_code(&body), None, "{body}");
    assert_eq!(status, 200);
    assert_eq!(hops(&h), 1);
}

// ══ THE ORDER OF THE TWO GATES, AND THEIR ORDER AGAINST THE PARSE ════════════════════════════════

#[tokio::test]
async fn the_media_type_is_judged_before_the_body_is_parsed() {
    // THE EXACT SHAPE THE TCK SENDS: a wrong media type carrying a body that is ALSO not JSON. A
    // gate that ran after the parse would answer ParseError (-32700) and never reach -32005, which
    // is precisely the answer busbar used to give and precisely what the suite reported.
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/planner", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .header("content-type", "text/plain")
        .header("A2A-Version", "1.0")
        .body("{'jsonrpc': '2.0', 'id': 1, 'method': 'SendMessage'}")
        .send()
        .await
        .expect("the call completes");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    assert_eq!(error_code(&body), Some(-32005), "{body}");
    assert_eq!(status, 415);
    assert_eq!(hops(&h), 0);
}
