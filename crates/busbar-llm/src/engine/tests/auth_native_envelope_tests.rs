// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM DIALECTS' AUTH-FAILURE SHAPES — relocated from core's `src/auth/tests/tests.rs` (1.6.0
//! Phase 4, batch 60 slot S01: a neutral crate's tests name no dialect, and a test that exercises a
//! named dialect lives with the plane that owns it).
//!
//! Core's auth path is dialect-blind: it resolves a path to an ingress, asks the registry which
//! dialect that ingress speaks, and hands the registered writer the bad-credential status, `kind`
//! and copy. WHICH dialect a path resolves to and WHAT that dialect's native bad-key answer looks
//! like are this plane's facts, so they are pinned here, in the plane's own unit-test binary, which
//! reaches the engine's fixture through the crate's `crate::test_support` doorway and this plane's
//! real dialect registrations through `crate::testkit::install_test_seams`.
//!
//! The sync `unauthorized_response` tests core ran against its private fn now drive the SAME
//! function through the real router and `auth_middleware` (a wrong credential in token mode), which
//! is the only way the auth-failure envelope reaches a client.

use crate::test_support::engine_kit::EngineTestKit as _;
use busbar_kernel::auth::AuthMiddleware;
use busbar_substrate_values::proto::vendor_auth_failure_message;
use reqwest::header::HeaderMap;
use reqwest::StatusCode;

/// This plane's registrations, installed into the kernel's process registries through the plane's
/// own test-kit install: the protocol declarations, the plane declaration, and the path / body
/// ingress tables a residual-arm auth failure reads.
fn install_llm_registrations() {
    crate::testkit::install_test_seams();
}

/// Helper: an `AuthCfg` whose data-plane chain names the given modules (bare entries).
fn chain_cfg(modules: &[&str]) -> busbar_kernel::config::auth::AuthCfg {
    busbar_kernel::config::auth::AuthCfg::with_chain(
        modules
            .iter()
            .map(|m| busbar_kernel::config::auth::AuthChainEntry::bare(*m))
            .collect(),
    )
}

/// The dialect an auth-failure envelope is shaped in for `path`, on a deployment with NO plane
/// mounted — the residual arm of the ONE resolver core's `unauthorized_response` reads. A mounted
/// plane's answer is a different arm entirely and is pinned where the mount lives.
fn residual_dialect(path: &str) -> &'static str {
    busbar_kernel::ingress::native::envelope_dialect(
        busbar_kernel::plane::PlaneDispatch::default().ingress_of(path),
    )
}

/// One auth failure as the client sees it: status, headers, and the JSON body.
struct AuthFailure {
    status: StatusCode,
    headers: HeaderMap,
    body: serde_json::Value,
}

impl AuthFailure {
    fn status(&self) -> StatusCode {
        self.status
    }
    fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

/// The JSON body of an auth failure, for shape assertions.
fn decode_body(resp: AuthFailure) -> serde_json::Value {
    resp.body
}

/// The auth-failure answer core's `unauthorized_response` gives `path`: a deployment in TOKEN mode
/// (the test-groups-module chain) with no plane mounted, so the path resolves through the residual
/// arm, and a wrong credential. Auth rejects before routing, so no upstream call is made; `TestApp`
/// still needs a lane/pool.
async fn unauthorized_response(path: &str) -> AuthFailure {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use std::sync::Arc;

    crate::test_support::engine_kit::CORE_ENGINE_KIT.metrics_init();
    let server = MockServer::new(Arc::new(MockServerState::new())).await;
    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();
    let router = crate::test_support::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let r = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .header("x-api-key", "wrong-token")
        .body(r#"{"model":"pa","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let bytes = r.bytes().await.expect("auth-failure body must collect");
    let body = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "auth-failure body for '{path}' must be valid JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    });

    handle.abort();
    server.shutdown().await;
    AuthFailure {
        status,
        headers,
        body,
    }
}

/// Assert a string is canonical UUID-v4 shaped: five dash-separated lowercase-hex groups of
/// lengths 8-4-4-4-12, with the version nibble == '4' and the variant nibble in {8,9,a,b}.
fn assert_uuid_v4_shaped(id: &str) {
    let segs: Vec<&str> = id.split('-').collect();
    assert_eq!(
        segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "x-amzn-requestid must be UUID-v4 shaped (8-4-4-4-12), got '{id}'"
    );
    assert!(
        id.chars()
            .all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "UUID must be lowercase hex with dashes only, got '{id}'"
    );
    // Version nibble: first char of the third group.
    assert_eq!(
        segs[2].chars().next(),
        Some('4'),
        "UUID version nibble must be 4, got '{id}'"
    );
    // Variant nibble: first char of the fourth group must be one of 8,9,a,b.
    assert!(
        matches!(segs[3].chars().next(), Some('8' | '9' | 'a' | 'b')),
        "UUID variant nibble must be 8/9/a/b, got '{id}'"
    );
}

#[test]
fn test_residual_dialect_inference() {
    install_llm_registrations();
    assert_eq!(
        residual_dialect("/v1beta/models/gemini-1.5:generateContent"),
        "gemini"
    );
    // The stable `v1` Gemini alias the router also registers (`/v1/models/*rest`). A colon
    // `:<action>` in the final segment is the Gemini generateContent/streamGenerateContent shape
    // → gemini (pins the single resolver's classification of this path shape so it cannot drift).
    assert_eq!(
        residual_dialect("/v1/models/gemini-pro:generateContent"),
        "gemini"
    );
    assert_eq!(
        residual_dialect("/v1/models/gemini-1.5-pro:streamGenerateContent"),
        "gemini"
    );
    // `/v1/models/...` WITHOUT a colon action is the OpenAI `model.retrieve` shape (`GET
    // /v1/models/{id}`) — shape the auth error as OpenAI so an OpenAI SDK gets a decodable body.
    assert_eq!(residual_dialect("/v1/models/gpt-4o"), "openai");
    // `/v1beta/models/...` is Gemini-only even without a colon (OpenAI has no v1beta surface).
    assert_eq!(residual_dialect("/v1beta/models/gemini-pro"), "gemini");
    assert_eq!(
        residual_dialect("/model/anthropic.claude/converse"),
        "bedrock"
    );
    assert_eq!(
        residual_dialect("/model/anthropic.claude/converse-stream"),
        "bedrock"
    );
    // A pool/model literally named "model" hitting `/model/v1/messages` must NOT be classified
    // as bedrock (no `/converse[-stream]` suffix) — it falls through to anthropic.
    assert_eq!(residual_dialect("/model/v1/messages"), "anthropic");
    // `/model/` prefix without a Converse suffix and without `/v1/messages` is unknown → openai.
    assert_eq!(residual_dialect("/model/foo/bar"), "openai");
    assert_eq!(residual_dialect("/v1/messages"), "anthropic");
    assert_eq!(residual_dialect("/pa/v1/messages"), "anthropic");
    assert_eq!(
        residual_dialect("/anthropic/claude/v1/messages"),
        "anthropic"
    );
    assert_eq!(residual_dialect("/v1/chat/completions"), "openai");
    assert_eq!(residual_dialect("/v2/chat"), "cohere");
    assert_eq!(residual_dialect("/v1/responses"), "responses");
    // Unknown → generic (openai-shaped) envelope.
    assert_eq!(residual_dialect("/stats"), "openai");
}

#[tokio::test]
async fn test_unauthorized_response_is_json_with_native_envelope() {
    install_llm_registrations();
    // Every supported ingress protocol must get its DISTINCTIVE native error SHAPE, not just
    // `application/json` — a wrong-shaped 401 is a deterministic proxy tell a native SDK
    // would choke on. One assertion per ingress-dialect classification arm.

    // Gemini → {"error":{"code":400,"message":..,"status":"INVALID_ARGUMENT"}}, HTTP 400. The
    // genuine Generative Language API does NOT return 401/UNAUTHENTICATED for a bad API key; it
    // returns HTTP 400 INVALID_ARGUMENT. A 401/UNAUTHENTICATED body is a tell the google-genai
    // SDK never sees from real Google on the bad-key path.
    let resp = unauthorized_response("/v1beta/models/x:generateContent").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body = decode_body(resp);
    assert_eq!(body["error"]["code"], 400, "gemini body: {body}");
    assert_eq!(
        body["error"]["status"], "INVALID_ARGUMENT",
        "gemini body: {body}"
    );

    // Gemini stable-v1 alias (`/v1/models/<m>:generateContent`) must shape IDENTICALLY to the
    // v1beta surface — an earlier bug mis-shaped it as an OpenAI 401.
    let resp = unauthorized_response("/v1/models/gemini-pro:generateContent").await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "stable-v1 gemini status"
    );
    let body = decode_body(resp);
    assert_eq!(body["error"]["code"], 400, "stable-v1 gemini body: {body}");
    assert_eq!(
        body["error"]["status"], "INVALID_ARGUMENT",
        "stable-v1 gemini body: {body}"
    );

    // Anthropic → top-level {"type":"error","error":{"type":"authentication_error",..}}.
    let resp = unauthorized_response("/pa/v1/messages").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = decode_body(resp);
    assert_eq!(body["type"], "error", "anthropic top-level type: {body}");
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "anthropic error.type: {body}"
    );

    // OpenAI → {"error":{"type":"authentication_error","code":"invalid_api_key",..}} (no
    // top-level type=error). The genuine OpenAI bad-key 401 body carries
    // `error.code: "invalid_api_key"`, which the official SDK surfaces as
    // `AuthenticationError.code`; emitting `code: null` is a deterministic proxy tell. The
    // writers pair that code ONLY with `error.type: "authentication_error"`, so the envelope
    // must carry that pairing on the most common failure path.
    let resp = unauthorized_response("/v1/chat/completions").await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "openai auth status"
    );
    let body = decode_body(resp);
    assert!(
        body.get("type").is_none(),
        "openai must NOT carry a top-level type: {body}"
    );
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "openai error.type must match the real bad-key body: {body}"
    );
    assert_eq!(
            body["error"]["code"], "invalid_api_key",
            "openai bad-key body must carry code=invalid_api_key (not null), the SDK-visible tell: {body}"
        );

    // Responses → {"error":{"type":"authentication_error","code":"invalid_api_key","param":null,..}}
    // (same OpenAI-family bad-key shape, with the SDK-visible code populated).
    let resp = unauthorized_response("/v1/responses").await;
    let body = decode_body(resp);
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "responses error.type must match the real bad-key body: {body}"
    );
    assert_eq!(
        body["error"]["code"], "invalid_api_key",
        "responses bad-key body must carry code=invalid_api_key (not null): {body}"
    );
    assert!(
        body["error"].get("param").is_some(),
        "responses envelope carries a param field: {body}"
    );

    // Cohere → bare {"message":..} with NO `error` and NO `type`.
    let resp = unauthorized_response("/v2/chat").await;
    let body = decode_body(resp);
    assert!(
        body.get("message").is_some(),
        "cohere body has a top-level message: {body}"
    );
    assert!(
        body.get("error").is_none() && body.get("type").is_none(),
        "cohere body must be bare (no error/type): {body}"
    );

    // Bedrock → {"__type":"AccessDeniedException","message":..}, HTTP 403, x-amzn-* headers.
    let resp = unauthorized_response("/model/anthropic.claude/converse").await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a Bedrock SigV4 auth failure is 403, not 401"
    );
    assert_eq!(
        resp.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("AccessDeniedException"),
        "Bedrock auth failure must carry x-amzn-errortype the AWS SDK types off"
    );
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .expect("Bedrock auth failure must carry a synthetic x-amzn-requestid")
        .to_string();
    // Real Bedrock x-amzn-RequestId is UUID-v4 shaped (8-4-4-4-12 lowercase hex). A flat
    // 32-hex-no-dashes value is a protocol tell — assert the canonical shape, not just presence.
    assert_uuid_v4_shaped(&req_id);
    let body = decode_body(resp);
    assert_eq!(
        body["__type"], "AccessDeniedException",
        "bedrock __type: {body}"
    );
    assert!(
        body.get("error").is_none(),
        "bedrock body uses __type, not an error object: {body}"
    );
}

/// Recursively collect every JSON string value reachable in `v` (object values, array elements,
/// and the leaf string itself), so a leak-vocabulary scan covers the message regardless of the
/// field the per-protocol writer placed it on (`error.message` / top-level `message` / `__type`).
fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|e| collect_strings(e, out)),
        serde_json::Value::Object(o) => o.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

#[tokio::test]
async fn test_unauthorized_body_carries_no_busbar_vocabulary() {
    install_llm_registrations();
    // Regression for the auth-model leak: the auth-failure wire body must NOT name busbar's
    // internal auth concepts. Previously the literal "invalid or disabled virtual key" (and
    // "unauthorized" / "admin unauthorized") were reflected verbatim into the native error body
    // — a deterministic proxy tell that also discloses the per-virtual-key enable/disable model.
    // Sweep EVERY supported ingress path (incl. the unknown-path fallback) and assert no leaked
    // token appears anywhere in the JSON. The invalid-vs-disabled distinction must also be gone.
    const FORBIDDEN: &[&str] = &[
        "virtual key",
        "client token",
        "client_token",
        "allowlist",
        "disabled",
        "passthrough",
        "busbar",
        "unauthorized", // busbar-internal reason wording, not vendor copy
        "admin",
    ];
    // The admin-path case (`/api/v1/admin/keys` → the inferred-protocol fallback) stays in core's
    // `src/auth/tests/tests.rs`, which calls `unauthorized_response` directly: over the real stack an
    // `/api/` path is answered by the admin surface, never by this envelope.
    let paths = [
        "/v1beta/models/x:generateContent", // gemini
        "/pa/v1/messages",                  // anthropic
        "/v1/chat/completions",             // openai
        "/v1/responses",                    // responses
        "/v2/chat",                         // cohere
        "/model/anthropic.claude/converse", // bedrock
        "/totally/unknown/path",            // unknown → openai fallback
    ];
    for path in paths {
        let body = decode_body(unauthorized_response(path).await);
        let mut strings = Vec::new();
        collect_strings(&body, &mut strings);
        for s in &strings {
            let lc = s.to_ascii_lowercase();
            for bad in FORBIDDEN {
                assert!(
                    !lc.contains(bad),
                    "auth-failure body for '{path}' leaked busbar vocabulary '{bad}': {body}"
                );
            }
        }
    }
}

#[test]
fn test_vendor_auth_failure_message_is_plausible_per_proto() {
    install_llm_registrations();
    // The wire message is keyed PURELY off the inferred protocol (independent of the failure
    // reason) and reads like genuine vendor copy. Lock the exact strings so a regression that
    // reintroduces busbar wording — or distinguishes invalid-vs-disabled — is caught.
    assert_eq!(
        vendor_auth_failure_message("anthropic"),
        "invalid x-api-key"
    );
    assert_eq!(
        vendor_auth_failure_message("openai"),
        "Incorrect API key provided."
    );
    assert_eq!(
        vendor_auth_failure_message("responses"),
        "Incorrect API key provided."
    );
    // Byte-for-byte the gemini codec's `GEMINI_BAD_KEY_MESSAGE`, pinned as a literal (like the five
    // siblings above) so this core auth test names no dialect module; gemini owns the const's value.
    assert_eq!(
        vendor_auth_failure_message("gemini"),
        "API key not valid. Please pass a valid API key."
    );
    assert_eq!(vendor_auth_failure_message("cohere"), "invalid api token");
    // AWS conveys AccessDenied via __type / x-amzn-errortype, not a message string.
    assert_eq!(vendor_auth_failure_message("bedrock"), "");
    // Any unknown future proto: a neutral credential message, never busbar vocabulary.
    assert_eq!(
        vendor_auth_failure_message("some-future-proto"),
        "authentication failed"
    );
}

#[test]
fn test_every_router_ingress_path_maps_to_non_fallback_proto() {
    install_llm_registrations();
    // Coupling guard (router route table ↔ the residual dialect resolver ↔ `protocol_for`). Each
    // real ingress path the router registers must resolve to a SPECIFIC proto, not the
    // unknown-path `openai` fallback applied via the final `else`. If a future route is added
    // without updating the residual classifier's path-shape arms, callers on that protocol would
    // silently get an OpenAI-shaped 401 — a partial defeat of the indistinguishability promise. We
    // assert the expected mapping explicitly (a sample path per registered ingress family), so a
    // regression is caught.
    let cases = [
        ("/v1/messages", "anthropic"),
        ("/somepool/v1/messages", "anthropic"),
        ("/v1/chat/completions", "openai"),
        ("/v2/chat", "cohere"),
        ("/v1/responses", "responses"),
        ("/v1beta/models/gemini-1.5:generateContent", "gemini"),
        // BOTH Gemini ingress prefixes the router registers must resolve to a
        // non-fallback proto. The stable `v1` alias was previously omitted here, masking the
        // missing `/v1/models/` arm in the residual classifier (a `:`-action path mis-shaped
        // as openai).
        ("/v1/models/gemini-pro:generateContent", "gemini"),
        ("/model/anthropic.claude/converse", "bedrock"),
        ("/model/anthropic.claude/converse-stream", "bedrock"),
    ];
    for (path, expected) in cases {
        assert_eq!(
            residual_dialect(path),
            expected,
            "router ingress path '{path}' must map to '{expected}', not the fallback"
        );
        // And the resolved proto must be a real protocol (never the dead `None` arm). Neutral
        // registry seam: a KNOWN protocol has a registered declaration (`decl_for`), reached
        // without naming the witnessed codec (`protocol_for`).
        assert!(
            busbar_kernel::proto::decl_for(residual_dialect(path)).is_some(),
            "proto for '{path}' must resolve to a known protocol"
        );
    }
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: an unauthenticated
/// POST to `/v2/chat` (Cohere) and `/v1/responses` (Responses) must be rejected 401 with the
/// RESPECTIVE protocol's native error envelope — not an Anthropic/OpenAI-shaped body. The
/// existing multi-carrier test only covers the Anthropic path, leaving these two protocol
/// envelopes untested on the auth boundary (an indistinguishability failure if regressed).
#[tokio::test]
async fn test_cohere_and_responses_ingress_token_mode_native_401() {
    install_llm_registrations();
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::test_support::engine_kit::CORE_ENGINE_KIT.metrics_init();

    // No upstream call is made — auth rejects before routing — but TestApp needs a lane/pool.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::test_support::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}]}).to_string();

    // Cohere `/v2/chat` → bare {"message":..}, no `error`, no `type`.
    let r_cohere = client
        .post(format!("http://{addr}/v2/chat"))
        .header("x-api-key", "wrong-token")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r_cohere.status().as_u16(), 401, "cohere wrong token → 401");
    assert_eq!(
        r_cohere
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r_cohere.json().await.unwrap();
    assert!(
        env.get("message").is_some(),
        "cohere 401 must carry a bare message: {env}"
    );
    assert!(
        env.get("error").is_none() && env.get("type").is_none(),
        "cohere 401 must be the bare envelope (no error/type): {env}"
    );

    // Responses `/v1/responses` → {"error":{"type":"authentication_error","code":"invalid_api_key",..}}
    // (the genuine OpenAI-family bad-key 401 carries the SDK-visible code=invalid_api_key, which
    // the writers pair with type=authentication_error).
    let r_resp = client
        .post(format!("http://{addr}/v1/responses"))
        .header("x-api-key", "wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_resp.status().as_u16(), 401, "responses wrong token → 401");
    assert_eq!(
        r_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r_resp.json().await.unwrap();
    assert_eq!(
        env["error"]["type"], "authentication_error",
        "responses 401 must carry error.type=authentication_error: {env}"
    );
    assert_eq!(
        env["error"]["code"], "invalid_api_key",
        "responses 401 must carry the SDK-visible code=invalid_api_key (not null): {env}"
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: a wrong token on the
/// Bedrock ingress path (`/model/<id>/converse`) must be rejected with HTTP 403 (NOT 401 —
/// a native SigV4 auth failure is 403) carrying `x-amzn-errortype: AccessDeniedException`, a
/// UUID-v4-shaped `x-amzn-requestid`, and a body whose `__type` is `AccessDeniedException`. The
/// existing end-to-end auth tests only cover anthropic/cohere/responses; the bedrock-specific
/// status + typing headers were exercised only by a direct `unauthorized_response` call that
/// bypasses the middleware → router stack, so a regression dropping the 403/headers in the full
/// pipeline would be uncaught.
#[tokio::test]
async fn test_bedrock_ingress_wrong_token_is_403_native_envelope() {
    install_llm_registrations();
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::test_support::engine_kit::CORE_ENGINE_KIT.metrics_init();

    // Auth rejects before routing, so no upstream call is made; TestApp still needs a lane/pool.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::test_support::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}).to_string();

    let r = client
        .post(format!("http://{addr}/model/anthropic.claude/converse"))
        .header("authorization", "Bearer wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status().as_u16(),
        403,
        "a Bedrock SigV4 auth failure must be 403, not 401 (got {})",
        r.status()
    );
    assert_eq!(
        r.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("AccessDeniedException"),
        "Bedrock auth failure must carry x-amzn-errortype the AWS SDK types off"
    );
    let req_id = r
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .expect("Bedrock auth failure must carry x-amzn-requestid")
        .to_string();
    assert_uuid_v4_shaped(&req_id);
    assert_eq!(
        r.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        env["__type"], "AccessDeniedException",
        "bedrock body must use __type=AccessDeniedException: {env}"
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: a wrong token on EITHER
/// registered Gemini ingress prefix — the `v1beta` surface (`/v1beta/models/<id>:generateContent`)
/// AND the stable `v1` alias (`/v1/models/<id>:generateContent`) — must be rejected with the
/// Gemini-native bad-key envelope: HTTP 400, `error.code == 400`, `error.status ==
/// "INVALID_ARGUMENT"` (a real Generative Language API bad key is 400 INVALID_ARGUMENT, NOT
/// 401/UNAUTHENTICATED). The stable-v1 path was previously mis-shaped as an OpenAI 401 because the
/// residual dialect classifier had no `/v1/models/` arm — this exercises both prefixes through the
/// full stack.
#[tokio::test]
async fn test_gemini_ingress_wrong_token_is_native_bad_key_envelope() {
    install_llm_registrations();
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::test_support::engine_kit::CORE_ENGINE_KIT.metrics_init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::test_support::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}).to_string();

    // Both registered Gemini ingress prefixes must produce the identical native bad-key envelope.
    for path in [
        "/v1beta/models/gemini-1.5:generateContent",
        "/v1/models/gemini-1.5:generateContent",
    ] {
        let r = client
            .post(format!("http://{addr}{path}"))
            .header("x-goog-api-key", "wrong-token")
            .body(body.clone())
            .send()
            .await
            .unwrap();

        assert_eq!(
            r.status().as_u16(),
            400,
            "a Gemini bad-key auth failure on '{path}' must be 400 INVALID_ARGUMENT (got {})",
            r.status()
        );
        assert_eq!(
            r.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        let env: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            env["error"]["code"], 400,
            "gemini error.code on '{path}': {env}"
        );
        assert_eq!(
            env["error"]["status"], "INVALID_ARGUMENT",
            "gemini error.status on '{path}' must be INVALID_ARGUMENT: {env}"
        );
    }

    handle.abort();
    server.shutdown().await;
}

// Relocated from core's `src/auth/tests/tests.rs` (batch 60 S10 residue): its assertion is the
// anthropic native envelope, a dialect fact core's synthetic protocol set does not carry.
/// Regression for the over-broad admin-prefix detection: a path that merely STARTS WITH the
/// bytes `/api` but is not a registered `/api/...` route (e.g. `/apix/...`) must NOT be
/// classified as admin. Under TOKEN mode with a wrong token it should be rejected by the normal
/// auth branch with the inferred-protocol native 401 envelope — never routed down the admin
/// branch (which would early-return without the `CallerToken` extension and 500 in a non-admin
/// handler). `/apix/v1/messages` infers the anthropic protocol via the `/v1/messages` suffix.
#[tokio::test]
async fn test_admin_prefix_is_boundary_safe() {
    install_llm_registrations();
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::test_support::engine_kit::CORE_ENGINE_KIT.metrics_init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("apix", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::test_support::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body =
        json!({"model": "apix", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Wrong token to `/apix/v1/messages`: rejected by the NORMAL auth branch, not the admin
    // branch — a normal-protocol native 401 (anthropic), NOT the admin "admin unauthorized"
    // path and NOT a 500 from a missing CallerToken extension.
    let r = client
        .post(format!("http://{addr}/apix/v1/messages"))
        .header("x-api-key", "wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "an /apix path with a wrong token must be a normal 401, not 500/admin-500 (got {})",
        r.status()
    );
    assert_eq!(
        r.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r.json().await.unwrap();
    // Anthropic native envelope (inferred from the `/v1/messages` suffix), proving the path was
    // shaped by the normal ingress branch rather than the admin branch.
    assert_eq!(
        env["type"], "error",
        "expected the /v1/messages native envelope: {env}"
    );
    assert_eq!(
        env["error"]["type"], "authentication_error",
        "expected the /v1/messages authentication_error: {env}"
    );

    handle.abort();
    server.shutdown().await;
}
