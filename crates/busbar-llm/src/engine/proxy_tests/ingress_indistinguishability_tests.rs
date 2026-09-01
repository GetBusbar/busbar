use super::{
    cross_protocol_error_kind, egress_accept, egress_user_agent, forward_with_pool, ingress_error,
    ingress_stream_content_type, read_capped, shape_cross_protocol_error, ReadEnd, UsageSink,
    KIND_AUTHENTICATION, KIND_INVALID_REQUEST, KIND_OVERLOADED, KIND_RATE_LIMIT,
};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::sync::Arc;

/// Mint a REAL `hyper::Error` (the owned egress client's stream error type — unconstructible by
/// hand): a one-shot local upstream declares a Content-Length it never delivers and slams the
/// connection, so the body stream yields a genuine incomplete-message transport error. Used
/// wherever a test injects a transport cut into `FirstByteBody`'s inner stream.
async fn hyper_transport_err() -> hyper::Error {
    use futures::StreamExt;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind err fixture");
    let addr = listener.local_addr().expect("err fixture addr");
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;
        sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial")
            .await
            .expect("write partial");
        // Drop: the connection dies with 93 declared bytes undelivered.
    });
    let client = crate::engine::build_egress_client(&crate::engine::EgressClientSpec::llm_lane(
        1, 1, false, false,
    ));
    let req = crate::engine::egress_request(
        format!("http://{addr}/").parse().expect("err fixture uri"),
        axum::http::HeaderMap::new(),
        bytes::Bytes::new(),
    );
    let resp = client.request(req).await.expect("headers must arrive");
    let mut body = resp.into_body().into_data_stream();
    loop {
        match body.next().await {
            Some(Ok(_)) => continue,
            Some(Err(e)) => return e,
            None => panic!("expected a mid-body transport error, got clean EOF"),
        }
    }
}

/// Every egress request must carry a native-SDK `Accept`
/// header — a native SDK always sends one, so its absence is a backend-side proxy fingerprint.
/// The headline bedrock egress must mirror botocore: `application/vnd.amazon.eventstream` for a
/// ConverseStream (stream) call, `application/json` for the unary Converse call.
#[test]
fn test_egress_accept_matches_native_sdk() {
    crate::testkit::install_test_seams();
    // Bedrock: eventstream on stream, json on unary (the botocore split).
    assert_eq!(
        egress_accept("bedrock", true),
        "application/vnd.amazon.eventstream"
    );
    assert_eq!(egress_accept("bedrock", false), "application/json");
    // REST/SSE backends: SSE on stream, json on unary.
    for p in ["anthropic", "openai", "responses", "gemini", "cohere"] {
        assert_eq!(egress_accept(p, true), "text/event-stream", "{p} stream"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(egress_accept(p, false), "application/json", "{p} unary");
    }
    // Unknown egress still gets a present, plausible Accept (never absent).
    assert_eq!(egress_accept("mystery", true), "text/event-stream"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(egress_accept("mystery", false), "application/json");
}

/// Every egress request must carry a native-SDK `User-Agent`
/// (a UA-less request is the most distinctive backend-side proxy fingerprint), and each per-protocol
/// UA embeds a PINNED SDK version that silently drifts from the real SDK over time. This test pins
/// each protocol to its `EGRESS_UA_*` constant so the version strings cannot be edited or drift
/// unnoticed — any change trips this test and forces a conscious bump (the in-code half of the
/// drift-containment; the release-checklist obligation is documented on the constant block). It
/// also guards the never-absent invariant: every branch, including the foreign-egress default,
/// returns a non-empty, plausibly-versioned UA.
#[test]
fn test_egress_ua_versions_are_pinned_and_present() {
    crate::testkit::install_test_seams();
    // GOLDEN WIRE LITERALS — the exact bytes a native SDK sends. Comparing against the
    // `EGRESS_UA_*` constants themselves is a tautology (both sides move together when the
    // constant is edited); pinning the literal here means changing a constant is a deliberate,
    // reviewed act that must touch BOTH this table and the constant, so it can never happen
    // silently. Copied verbatim from the current `EGRESS_UA_*` values in egress.rs — this fix pins
    // the status quo, it does not change any wire value.
    assert_eq!(
        egress_user_agent("anthropic"),
        "Anthropic/Python 0.39.0",
        "anthropic egress UA drifted from the pinned native-SDK string"
    );
    assert_eq!(
        egress_user_agent("openai"),
        "OpenAI/Python 1.54.0",
        "openai egress UA drifted from the pinned native-SDK string"
    );
    assert_eq!(
        egress_user_agent("responses"),
        "OpenAI/Python 1.54.0",
        "responses egress UA drifted from the pinned native-SDK string"
    );
    assert_eq!(
        egress_user_agent("gemini"),
        "google-genai-sdk/0.8.0 gl-python/3.11",
        "gemini egress UA drifted from the pinned native-SDK string"
    );
    assert_eq!(
        egress_user_agent("bedrock"),
        "Boto3/1.35.0 md/Botocore#1.35.0",
        "bedrock egress UA drifted from the pinned native-SDK string"
    );
    assert_eq!(
        egress_user_agent("cohere"),
        "cohere-python/5.11.0",
        "cohere egress UA drifted from the pinned native-SDK string"
    );
    // Foreign/unknown egress still gets a present, plausible UA (never empty / never absent).
    assert_eq!(
        egress_user_agent("mystery"),
        "okhttp/4.12.0",
        "mystery/default egress UA drifted from the pinned literal"
    );
    for p in [
        "anthropic",
        "openai",
        "responses",
        "gemini",
        "bedrock",
        "cohere",
        "mystery",
    ] {
        let ua = egress_user_agent(p);
        assert!(!ua.is_empty(), "{p} egress UA must never be empty");
        // Each native-SDK UA carries a version token (a `/` or `#` separated number) — the exact
        // shape a backend keys off; a versionless UA would itself be a tell.
        assert!(
            ua.chars().any(|c| c.is_ascii_digit()),
            "{p} egress UA must carry a version number: {ua}"
        );
    }
    // The Stainless-generated Python SDKs (OpenAI + Anthropic) emit the SAME
    // `<Title>/Python <ver>` grammar. Emitting a different shape for one (the old
    // `anthropic-sdk-python/<ver>`) was a wire tell distinguishing proxied from native traffic.
    // Assert BOTH match the shared grammar so the anthropic UA can never silently drift back.
    // Read the two Python-SDK UAs through the registry wrapper (their literals now live on the LLM
    // plugin's decls, not on a core `EGRESS_UA_*` const this test could name).
    for ua in [egress_user_agent("anthropic"), egress_user_agent("openai")] {
        let (title, rest) = ua.split_once('/').expect("Python-SDK UA contains a '/'");
        assert!(
            title.chars().next().is_some_and(|c| c.is_ascii_uppercase()),
            "Stainless Python SDK UA must start with a capitalized Title: {ua}"
        );
        assert!(
            rest.starts_with("Python "),
            "Stainless Python SDK UA must be `<Title>/Python <ver>`: {ua}"
        );
    }
}

/// CANONICAL status→kind mapping shared by the main and degraded cross-protocol error shaping.
/// A 401/403 must map to authentication_error/
/// permission_error, NOT invalid_request_error (the degraded-path bug). Exhaustive over the
/// status arms the mapping distinguishes.
#[test]
fn test_cross_protocol_error_kind_mapping() {
    crate::testkit::install_test_seams();
    assert_eq!(
        cross_protocol_error_kind(StatusCode::UNAUTHORIZED),
        "authentication_error" // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        cross_protocol_error_kind(StatusCode::FORBIDDEN),
        "permission_error" // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        cross_protocol_error_kind(StatusCode::TOO_MANY_REQUESTS),
        "rate_limit_error" // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        cross_protocol_error_kind(StatusCode::INTERNAL_SERVER_ERROR),
        "api_error" // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        cross_protocol_error_kind(StatusCode::BAD_GATEWAY),
        "api_error" // golden wire-contract literal (kept bare on purpose)
    );
    // A genuine upstream 503 must map to `overloaded`, NOT `api_error`.
    // Collapsing it into `api_error` would emit, on a bedrock ingress, the
    // 503/InternalServerException pairing the real AWS runtime never produces (503 pairs with
    // ServiceUnavailableException). `overloaded` is the kind busbar already uses for its own 503s.
    assert_eq!(
        cross_protocol_error_kind(StatusCode::SERVICE_UNAVAILABLE),
        "overloaded" // golden wire-contract literal (kept bare on purpose)
    );
    // 504 maps to the timeout class, distinct from the generic 5xx `api_error`.
    assert_eq!(
        cross_protocol_error_kind(StatusCode::GATEWAY_TIMEOUT),
        "timeout" // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        cross_protocol_error_kind(StatusCode::BAD_REQUEST),
        "invalid_request_error" // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        cross_protocol_error_kind(StatusCode::NOT_FOUND),
        "invalid_request_error" // golden wire-contract literal (kept bare on purpose)
    );
}

/// `shape_cross_protocol_error` (the shared finalizer used by BOTH `forward_with_pool` and
/// `forward_once`) reshapes a crossed-boundary non-2xx into the ingress-native envelope with the
/// canonical kind. REGRESSION: a 401 from an OpenAI backend reaching an Anthropic client must be
/// `authentication_error`, a 403 `permission_error` — matching the main path, not the old
/// degraded-path `invalid_request_error`.
#[tokio::test]
async fn test_shape_cross_protocol_error_auth_kinds() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    for (status, want_kind) in [
        (StatusCode::UNAUTHORIZED, "authentication_error"), // golden wire-contract literal (kept bare on purpose)
        (StatusCode::FORBIDDEN, "permission_error"), // golden wire-contract literal (kept bare on purpose)
    ] {
        let resp =
            shape_cross_protocol_error("anthropic", status, br#"{"error":{"message":"nope"}}"#);
        assert_eq!(resp.status(), status, "status preserved");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["error"]["type"], want_kind,
            "cross-protocol {status} must map to {want_kind} (matches the main path)"
        );
        assert_eq!(
            v["error"]["message"], "nope",
            "upstream human message is lifted into the native envelope"
        );
    }
}

/// A Bedrock-ingress forward-layer error must
/// carry BOTH `x-amzn-RequestId` and `x-amzn-errortype` (mirroring the body `__type`), exactly
/// like a real AWS Bedrock runtime error and like ingress/auth.rs. Non-bedrock ingress must NOT
/// carry them.
#[test]
fn test_ingress_error_bedrock_amzn_headers() {
    crate::testkit::install_test_seams();
    let resp = ingress_error(
        "bedrock",
        StatusCode::TOO_MANY_REQUESTS,
        KIND_RATE_LIMIT,
        "slow down",
    );
    assert!(
        resp.headers().get("x-amzn-requestid").is_some(),
        "bedrock error must carry x-amzn-RequestId"
    );
    let errtype = resp
        .headers()
        .get("x-amzn-errortype")
        .and_then(|h| h.to_str().ok());
    // `KIND_RATE_LIMIT` maps to `ThrottlingException`, pinned as a literal so this core test names no
    // dialect module; the mapping's identity is proven beside the bedrock codec in `busbar-llm`
    // (`src/tests/proto/phase1_5_relocated_tests.rs`).
    assert_eq!(
        errtype,
        Some("ThrottlingException"),
        "x-amzn-errortype mirrors the body __type"
    );

    // Non-bedrock ingress: no amzn headers.
    let oai = ingress_error("openai", StatusCode::BAD_REQUEST, KIND_INVALID_REQUEST, "x");
    assert!(
        oai.headers().get("x-amzn-requestid").is_none()
            && oai.headers().get("x-amzn-errortype").is_none(),
        "non-bedrock ingress error must NOT carry x-amzn-* headers"
    );
}

/// A forward-layer error returned to the CLIENT must carry the INGRESS protocol's native JSON
/// error envelope (not `text/plain`), with the status code preserved. For an Anthropic ingress
/// the shape is `{"type":"error","error":{"type",...,"message"}}` — what `anthropic.APIStatusError`
/// decodes.
#[tokio::test]
async fn test_ingress_error_emits_native_envelope_with_status() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    let resp = ingress_error(
        "anthropic",
        StatusCode::BAD_REQUEST,
        KIND_INVALID_REQUEST,
        "router: bad json: trailing comma",
    );
    assert_eq!(resp.status().as_u16(), 400, "status code is preserved");
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"), // golden wire-contract literal (kept bare on purpose)
        "native error envelope is served as application/json, never text/plain"
    );
    // Body is the Anthropic-native error shape.
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["type"], "error",
        "Anthropic error envelope: top-level type"
    );
    assert_eq!(
        v["error"]["type"],
        "invalid_request_error", // golden wire-contract literal (kept bare on purpose)
        "Anthropic typed error kind"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("bad json"),
        "human-readable detail preserved: {v}"
    );

    // OpenAI ingress gets the OpenAI envelope shape instead, same status.
    let oai = ingress_error(
        "openai",
        StatusCode::SERVICE_UNAVAILABLE,
        KIND_OVERLOADED,
        "router: all lanes exhausted; retry after 3s",
    );
    assert_eq!(oai.status().as_u16(), 503);
    assert_eq!(
        oai.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json") // golden wire-contract literal (kept bare on purpose)
    );
    // OpenAI ingress must NOT receive the anthropic-only `request-id` header.
    assert!(
        oai.headers().get("request-id").is_none(),
        "non-anthropic ingress must not carry an anthropic request-id header"
    );
}

/// The anthropic-ingress error `request-id` HEADER equals
/// the body `request_id`, and non-anthropic ingress carries no such header.
#[tokio::test]
async fn test_anthropic_ingress_error_request_id_header_matches_body() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    let resp = ingress_error(
        "anthropic",
        StatusCode::BAD_REQUEST,
        KIND_INVALID_REQUEST,
        "bad json",
    );
    let header_rid = resp
        .headers()
        .get("request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .expect("anthropic error must carry a request-id header");
    assert!(
        header_rid.starts_with("req_"),
        "request-id header carries the Anthropic req_ shape; got {header_rid}"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["request_id"].as_str(),
        Some(header_rid.as_str()),
        "the request-id header MUST equal the body request_id so they agree"
    );
}

/// The streaming response Content-Type is driven by the ingress protocol, not the upstream:
/// SSE protocols → `text/event-stream`; bedrock → `application/vnd.amazon.eventstream`.
#[test]
fn test_ingress_stream_content_type_by_protocol() {
    crate::testkit::install_test_seams();
    for p in ["openai", "anthropic", "gemini", "cohere", "responses"] {
        assert_eq!(ingress_stream_content_type(p), Some("text/event-stream"));
        // golden wire-contract literal (kept bare on purpose)
    }
    assert_eq!(
        ingress_stream_content_type("bedrock"),
        Some("application/vnd.amazon.eventstream")
    );
    assert_eq!(ingress_stream_content_type("nonsense"), None);
}

/// Cross-protocol non-stream response: an OpenAI backend whose body carries a `chatcmpl-` id
/// must NOT leak that foreign id to an Anthropic client. The translation seam strips the IR
/// identity before the ingress writer runs, so the writer mints a NATIVE `msg_` id, and the
/// response is served with the INGRESS Content-Type (`application/json`).
#[tokio::test]
async fn test_cross_protocol_response_carries_ingress_ct_and_native_id() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // OpenAI-shaped backend response with a foreign `chatcmpl-` id + created + fingerprint.
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-LEAK123",
                "object": "chat.completion",
                "created": 1234567890,
                "system_fingerprint": "fp_backend",
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
            }),
        });
    let server = MockServer::new(state.clone()).await;

    // Lane speaks OpenAI; ingress is Anthropic → cross-protocol translation hop.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("pa", &[(0, 1)])
        .build();

    let body = serde_json::to_vec(
        &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
    )
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pa",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    // Ingress-driven Content-Type for a non-stream cross-protocol response.
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "non-stream cross-protocol response uses the ingress JSON Content-Type"
    );

    use http_body_util::BodyExt as _;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    // Native Anthropic message shape.
    assert_eq!(v["type"], "message", "Anthropic message envelope");
    let id = v["id"].as_str().unwrap_or("");
    assert!(
        id.starts_with("msg_"),
        "Anthropic client must receive a NATIVE msg_ id, got: {id}"
    );
    assert!(
        !id.contains("chatcmpl-"),
        "the OpenAI backend's chatcmpl- id must NOT leak to the Anthropic client; got: {id}"
    );
    // The whole serialized body must be free of the leaked backend identity.
    let raw = String::from_utf8_lossy(&bytes);
    assert!(
        !raw.contains("chatcmpl-LEAK123"),
        "no foreign id anywhere in the translated response: {raw}"
    );
    assert!(
        !raw.contains("fp_backend"),
        "backend system_fingerprint must not leak across protocols: {raw}"
    );
    server.shutdown().await;
}

/// A cross-protocol non-stream 2xx whose `usage` block
/// PARSES but whose content shape is UNMODELED (here an empty `choices` array, on which the OpenAI
/// reader's `read_response` returns `Err`) must NOT charge the virtual key's token budget. The body
/// is untranslatable, so the client receives a 500 with NO completion; billing it (the old code
/// called `record_nonstream_usage` BEFORE proving translation succeeds) contradicts the
/// charge-only-on-delivery policy the Truncated/TransportError branches already honor. Asserts the
/// response is the ingress-native 500 AND that the gov budget recorded ZERO spend.
#[tokio::test]
async fn test_untranslatable_2xx_does_not_charge_tokens() {
    crate::testkit::install_test_seams();
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // OpenAI-shaped 2xx: a real `usage` block (so the tap WOULD count 7+3=10 tokens) but an EMPTY
    // `choices` array — the OpenAI reader rejects this in `read_response`, so it is untranslatable.
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "chatcmpl-EMPTY",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "glm-4.5",
            "choices": [],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}
        }),
    });
    let server = MockServer::new(state.clone()).await;

    // Gov + a virtual key. Spend is DERIVED now, so the "no token billing" intent is asserted on
    // the token ledger itself: a zero post-call token count proves no token billing happened (the
    // tap WOULD have ledgered 7+3=10 tokens if it wrongly ran).
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let charged_at: u64 = 1_700_000_000;
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    // Lane speaks OpenAI; ingress is Anthropic → cross-protocol translation hop.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("pa", &[(0, 1)])
        .build();

    let body = serde_json::to_vec(
        &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
    )
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pa",
        None,
        "anthropic",
        crate::test_support::CHAT,
        sink,
    )
    .await;

    // The untranslatable body yields an ingress-native 500 with NO completion delivered.
    assert_eq!(
        resp.status().as_u16(),
        500,
        "an untranslatable cross-protocol 2xx must surface an ingress-native 500"
    );

    // ...and the key's token ledger must be UNTOUCHED (the bug ledgered 10 tokens here).
    let tokens = gov
        .usage_for(&cost, &key.id, charged_at)
        .expect("usage read")
        .map(|u| u.tokens)
        .unwrap_or(0);
    assert_eq!(
        tokens, 0,
        "an undelivered (untranslatable) completion must NOT charge the token budget"
    );
    server.shutdown().await;
}

/// The untranslatable-2xx fallthrough must ALSO refund the headers-time lane budget unit AND record
/// a breaker transient (the BREAKER half matters more than the budget half: today a lane returning
/// undecodable 200s forever never trips). Same MockServer shape as
/// `test_untranslatable_2xx_does_not_charge_tokens` (empty `choices`, so the OpenAI reader's
/// `read_response` rejects it), but the lane is budget-limited to 1 and the pool's breaker is
/// configured to trip on a single consecutive failure, so ONE untranslatable response must both
/// return the unit and flip the cell to Open.
#[tokio::test]
async fn test_untranslatable_2xx_refunds_budget_and_trips_breaker() {
    crate::testkit::install_test_seams();
    use busbar_core::store::{BreakerCfg, BreakerState, TripConfig, TripMode};
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "chatcmpl-EMPTY",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "glm-4.5",
            "choices": [],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}
        }),
    });
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai")
            .budget(1),
        )
        .pool("pa", &[(0, 1)])
        .pool_breaker(
            "pa",
            &BreakerCfg {
                trip: TripConfig {
                    mode: TripMode::Consecutive,
                    consecutive_n: 1,
                    ..TripConfig::default()
                },
                ..BreakerCfg::default()
            },
        )
        .build();

    assert_eq!(app.store.lane_budget_remaining(0), Some(1));
    // A prior optimistic success, exactly as the 2xx-headers path records before this arm runs, so
    // the pool cell has something for the compensating transient to reverse.
    app.store.record_success_in("pa", 0);
    assert!(matches!(
        app.store.breaker_state_in("pa", 0),
        BreakerState::Closed
    ));

    let body = serde_json::to_vec(
        &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
    )
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pa",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 500);
    assert_eq!(
        app.store.lane_budget_remaining(0),
        Some(1),
        "the untranslatable-2xx fallthrough must refund the headers-time spend_budget unit"
    );
    assert!(
        matches!(
            app.store.breaker_state_in("pa", 0),
            BreakerState::Open { .. }
        ),
        "one consecutive untranslatable 2xx (consecutive_n=1) must trip the pool cell to Open"
    );
    server.shutdown().await;
}

/// A SAME-PROTOCOL NON-STREAM 2xx
/// `application/json` body whose top-level object splits across transport frames BEFORE its
/// trailing `usage` must STILL be token-counted. The streaming per-poll `tap.feed` scanner keeps
/// no cross-chunk state — it only parses complete JSON objects within a single chunk — so the old
/// code parsed NO usage on a multi-chunk same-protocol non-stream body, leaving input/output
/// tokens `None`, charging 0 tokens, and undercounting the key's TPM/spend on a mainstream config
/// (OpenAI→OpenAI). The fix buffers the non-SSE body (bounded) and runs `feed_whole` ONCE over the
/// reassembled body at stream end. Drives `FirstByteBody` directly (the harness cannot force a
/// transport-frame split end-to-end) with a body deliberately split before `usage`, then asserts
/// the gov recorded the tokens (the old code would record 0 → spend 0).
#[tokio::test]
async fn test_same_protocol_nonstream_multichunk_counts_usage() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();

    // Gov + virtual key. Spend is DERIVED now, so "the tail usage was counted" is asserted on the
    // token ledger: a 1000-token post-drain ledger proves the reassembled body's `usage` ran.
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let charged_at: u64 = 1_700_000_000;
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    // An OpenAI chat.completion 2xx with 600 input + 400 output = 1000 tokens, with `usage` at the
    // TAIL (real wire order). Split the wire bytes into two chunks at a point BEFORE `"usage"`, so
    // neither chunk contains a complete top-level object — the exact cross-frame split that proves
    // billing reassembles the whole body before running the IR reader. The
    // client still receives the bytes verbatim; only a bounded copy is retained for the IR read.
    let body = r#"{"id":"chatcmpl-split","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":600,"completion_tokens":400}}"#;
    let split = body.find(r#""usage""#).expect("usage marker present");
    assert!(split > 0 && split < body.len(), "split must be interior");
    let chunk1 = Bytes::from(body[..split].to_string());
    let chunk2 = Bytes::from(body[split..].to_string());

    // Minimal App for the lane/store the FirstByteBody refunds/breaker arms reference (unused on
    // this clean non-SSE drain, but required by the constructor).
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "glm-4.5",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();

    // Same-protocol non-stream: is_sse=false, translate=None, ingress non-bedrock ("openai").
    let inner = futures::stream::iter(vec![
        Ok::<Bytes, hyper::Error>(chunk1),
        Ok::<Bytes, hyper::Error>(chunk2),
    ]);
    let fbb = FirstByteBody::new(
        inner,
        false, // is_sse: same-protocol NON-STREAM application/json
        "openai",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        Arc::new(busbar_core::store::BreakerCfg::default()),
        "pa",
        None, // translate: same-protocol → no translation
        None, // json_array
        sink,
        false, // budget_spent
    );

    // Drain the body fully (drives poll_next to Poll::Ready(None), firing the IR read + record).
    let collected = fbb
        .into_body()
        .collect()
        .await
        .expect("drain body")
        .to_bytes();
    // The client still receives the full body incrementally (bytes are unchanged).
    assert_eq!(
        collected.as_ref(),
        body.as_bytes(),
        "the client must still receive the complete body verbatim"
    );

    // The reassembled body's 1000 tokens must have been ledgered (old code: 0). Accrual may land
    // off the polling task, so poll until the tokens appear (bounded retries) before asserting.
    let mut tokens = 0;
    for _ in 0..200 {
        tokio::task::yield_now().await;
        tokens = gov
            .usage_for(&cost, &key.id, charged_at)
            .expect("usage read")
            .map(|u| u.tokens)
            .unwrap_or(0);
        if tokens == 1000 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert_eq!(
        tokens, 1000,
        "a multi-chunk same-protocol non-stream body's tail usage MUST be counted (1000 tokens)"
    );
}

/// BILLING-TRUNCATION regression (MEDIUM): a same-protocol non-stream `application/json` body
/// LARGER than the usage-tap reassembly cap (`nonstream_buf`, capped at
/// `max_translated_body_bytes()`) must still bill its trailing `usage` object correctly. The client
/// always receives the body byte-for-byte regardless (asserted below); this test is about the
/// SEPARATE billing-only copy.
///
/// Before the fix, `nonstream_buf` was HEAD-truncated: bytes past the cap were simply dropped, so
/// once the body exceeded the cap the retained prefix never reached the tail `usage` object (every
/// dialect places `usage` at/near the end) — `extract_usage` parsed nothing, and the request billed
/// ZERO tokens despite the client receiving the full, valid completion. After the fix, the buffer is
/// TAIL-anchored (drops from the FRONT once over cap), so the trailing `usage` object survives and
/// is recovered even from a fragment whose head is gone (`usage::recover_truncated_usage`).
///
/// Uses a small test cap (via `InstallGuard`, not the 32 MiB production default) so the over-cap
/// body doesn't need to be enormous, and drives `FirstByteBody` directly with the body split across
/// several transport-frame-sized chunks (mirroring `test_same_protocol_nonstream_multichunk_counts_usage`).
#[tokio::test]
async fn test_same_protocol_nonstream_over_cap_body_still_bills_tail_usage() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    use bytes::Bytes;
    use http_body_util::BodyExt as _;

    busbar_core::metrics::init();
    let _lock = busbar_core::limits::LIMITS_TEST_LOCK.lock().await;
    // A cap small enough that the filler content alone blows well past it, but the RAII guard
    // restores whatever was installed before this test regardless of how it exits.
    const CAP: usize = 4096;
    let _limits_guard = busbar_core::limits::InstallGuard::install(
        &busbar_core::config::LimitsResolved::with_request_body_max_bytes(CAP),
    );
    assert_eq!(super::max_translated_body_bytes(), CAP);

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let charged_at: u64 = 1_700_000_000;
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    // A filler `content` string well over CAP bytes, so the whole body is > CAP and, under the old
    // head-truncate code, the retained prefix would end well before the tail `usage` object.
    let filler = "x".repeat(CAP * 3);
    let body = format!(
        r#"{{"id":"chatcmpl-huge","object":"chat.completion","choices":[{{"index":0,"message":{{"role":"assistant","content":"{filler}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":600,"completion_tokens":400}}}}"#
    );
    assert!(
        body.len() > CAP * 2,
        "body must genuinely exceed the test cap for this to be a meaningful regression test"
    );

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "glm-4.5",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();

    // Split into small transport-frame-sized chunks, same shape reqwest delivers a large body in.
    let chunks: Vec<Result<Bytes, hyper::Error>> = body
        .as_bytes()
        .chunks(512)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let inner = futures::stream::iter(chunks);
    let fbb = FirstByteBody::new(
        inner,
        false, // is_sse: same-protocol NON-STREAM application/json
        "openai",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        Arc::new(busbar_core::store::BreakerCfg::default()),
        "pa",
        None, // translate: same-protocol → no translation
        None, // json_array
        sink,
        false, // budget_spent
    );

    let collected = fbb
        .into_body()
        .collect()
        .await
        .expect("drain body")
        .to_bytes();
    // The client must receive the COMPLETE body verbatim, unaffected by the billing-only buffer's
    // tail-anchoring — telemetry must never change what is served.
    assert_eq!(
        collected.as_ref(),
        body.as_bytes(),
        "the client must still receive the complete over-cap body verbatim"
    );

    let mut tokens = 0;
    for _ in 0..200 {
        tokio::task::yield_now().await;
        tokens = gov
            .usage_for(&cost, &key.id, charged_at)
            .expect("usage read")
            .map(|u| u.tokens)
            .unwrap_or(0);
        if tokens == 1000 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert_eq!(
        tokens, 1000,
        "an over-cap same-protocol non-stream body's tail usage MUST still be billed (1000 tokens); \
         the old head-truncate code billed 0 here because the retained prefix never reached the \
         tail `usage` object"
    );
}

/// The non-stream usage-tap reassembly decision at
/// `response_body.rs`'s `if this.nonstream_buf.len() < max_translated_body_bytes() { let remaining
/// = max_translated_body_bytes() - ... }` reads the live-reloadable
/// `busbar_substrate::proxy::max_translate_body_bytes()` TWICE. `InstallGuard::install` (`limits.rs:74`)
/// mutates that `RwLock` under a still-running gateway (a config apply/rollback), so a write
/// landing in the gap between the two reads makes the first read's `if` pass on a HIGH cap while
/// the second read subtracts against a freshly-LOWERED one — an underflow (`remaining = lo - buf`)
/// that panics in debug and wraps to ~2^64 in release (silently disabling the cap).
///
/// This is a genuine two-statement TOCTOU with NO await point between the reads (`poll_next` is
/// synchronous), so there is no way to deterministically interleave a config apply between them
/// without instrumenting production code. This test instead applies RACE PRESSURE: a background
/// thread hammers `busbar_core::limits::install` between a cap comfortably above `CHUNK1_LEN` and one
/// below it, at the highest rate the toggling loop can sustain, while the foreground repeatedly
/// drives a fresh `FirstByteBody` through the exact vulnerable decision (buffer `CHUNK1_LEN` bytes
/// under the current cap, then poll a second chunk that re-reads the cap). Over enough attempts
/// the race window is hit. After the fix (`cap` read once into a local) this can NEVER panic
/// regardless of scheduling, so a passing run after the fix is not luck — it is deterministic.
///
/// `#[ignore]`: `busbar_core::limits::install` (test-only escape hatch) mutates the SAME process-global
/// `RwLock` every other test reads through `max_translated_body_bytes()`/`translate_body_max_bytes()`
/// with no cross-test serialization (see `limits.rs`'s own doc — this is a bare test-only setter,
/// not scoped). Hammering it from a background thread — required to have any chance of landing the
/// TOCTOU window — corrupted a concurrently-running sibling
/// (`test_cross_protocol_nonstream_over_cap_body_returns_500_uncharged`) under the default parallel
/// `cargo test` runner. Run it explicitly and alone:
/// `cargo test -p busbar --bin busbar -- --ignored --test-threads=1 nonstream_tap_cap_is_read_once_per_decision`.
#[test]
#[ignore = "hammers the global limits RwLock; run alone (see doc comment) to avoid corrupting sibling tests"]
fn nonstream_tap_cap_is_read_once_per_decision() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    use bytes::Bytes;
    use futures::StreamExt;
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicBool, Ordering};

    busbar_core::metrics::init();
    const CHUNK1_LEN: usize = 4096;
    const ATTEMPTS: usize = 20_000;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();

    // A real UsageSink (not just `Some(..)`) so the decision runs the exact production condition
    // (`taps_nonstream_usage() && usage_sink.is_some()`) that gates this branch — never reached
    // to completion here (only 2 chunks are polled, never draining to the billing arm), so no
    // background flush task is required.
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at: 1_700_000_000,
        admit: None,
    });

    let chunk1 = Bytes::from(vec![b'a'; CHUNK1_LEN]);
    let chunk2 = Bytes::from(vec![b'b'; 64]);

    // Race pressure: flip the live cap as fast as possible between a value that lets the first
    // read's `if` pass (comfortably above CHUNK1_LEN) and one the second read's subtraction cannot
    // survive (below CHUNK1_LEN) — the exact live-reload race `limits.rs`'s own header documents.
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let toggler = std::thread::spawn(move || {
        let hi = busbar_core::config::LimitsResolved::with_request_body_max_bytes(CHUNK1_LEN * 10);
        let lo = busbar_core::config::LimitsResolved::with_request_body_max_bytes(CHUNK1_LEN / 2);
        while !stop2.load(Ordering::Relaxed) {
            busbar_core::limits::install(&hi);
            busbar_core::limits::install(&lo);
        }
    });

    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let mut hit = false;
    for _ in 0..ATTEMPTS {
        let inner = futures::stream::iter(vec![
            Ok::<Bytes, hyper::Error>(chunk1.clone()),
            Ok::<Bytes, hyper::Error>(chunk2.clone()),
        ]);
        let mut fbb = FirstByteBody::new(
            inner,
            false, // is_sse: same-protocol NON-STREAM application/json
            "openai",
            crate::test_support::CHAT,
            (),
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
            app.clone(),
            0,
            Arc::new(busbar_core::store::BreakerCfg::default()),
            "pa",
            None,
            None,
            sink.clone(),
            false,
        );
        // Drive chunk 1 to completion (buffers CHUNK1_LEN bytes, whatever the cap happens to be at
        // that instant — retried by the outer loop if it lands unlucky and truncates early).
        loop {
            match fbb.poll_next_unpin(&mut cx) {
                std::task::Poll::Ready(Some(_)) => break,
                std::task::Poll::Ready(None) => break,
                std::task::Poll::Pending => continue,
            }
        }
        // The vulnerable decision: chunk 2 re-reads the cap while the toggler hammers it.
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| loop {
            match fbb.poll_next_unpin(&mut cx) {
                std::task::Poll::Ready(_) => break,
                std::task::Poll::Pending => continue,
            }
        }));
        if result.is_err() {
            hit = true;
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    toggler.join().unwrap();

    assert!(
        !hit,
        "the cap decision must read `max_translated_body_bytes()` ONCE: a second read landing \
         after a concurrent config apply lowered the cap underflowed `remaining` and panicked \
         (attempt to subtract with overflow) within {ATTEMPTS} attempts under race pressure"
    );
}

/// CHARACTERIZATION, FULL PATH: terminal token usage MUST reach the client on a
/// cross-protocol STREAM even when the egress reports usage in a SEPARATE trailing chunk (the OpenAI
/// `include_usage` convention). This drives the REAL `FirstByteBody` translate → finish → json-array
/// framer path for a gemini-ingress / openai-egress stream — the level the isolated translator tests
/// never reached. It fails both for the zero-usage bug (the
/// trailing usage chunk is dropped) AND for any repair that emits the terminal frame from a discarded
/// `finish()` (the gemini json-array close throws finish() away). The client's gemini json-array body
/// must carry `usageMetadata.promptTokenCount == 600` (the real value), not 0/absent.
#[tokio::test]
async fn test_cross_protocol_stream_delivers_trailing_usage_gemini_json_array() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();

    // OpenAI egress stream with include_usage: the finish chunk carries `usage: null`, and the REAL
    // usage arrives in a separate choices-empty trailing chunk, then `[DONE]`.
    let frames = [
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n",
        "data: [DONE]\n\n",
    ];
    let inner = futures::stream::iter(
        frames
            .iter()
            .map(|f| Ok::<Bytes, hyper::Error>(Bytes::from(f.as_bytes().to_vec())))
            .collect::<Vec<_>>(),
    );

    // Neutral seam: build the streaming translator by NAME through the installed factory
    // (`new_stream_translator`, the exact seam both forward paths use), so this core FirstByteBody
    // test names no witnessed codec type. `is_sse = true` + ingress != egress reproduces the prior
    // direct translator construction byte-for-byte.
    let translate =
        busbar_core::proto::new_stream_translator("gemini", "openai", true).expect("translator");
    // Neutral seam: the array-stream framer is built the exact way production builds it
    // (`decl_for(name).dialect().make_array_stream_framer()`), so this test names no dialect module.
    let json_array: Box<dyn busbar_core::proto::ArrayStreamFramer> =
        busbar_core::proto::decl_for("gemini")
            .and_then(|d| d.dialect())
            .and_then(|dc| dc.make_array_stream_framer())
            .expect("gemini dialect builds an array-stream framer");
    let fbb = FirstByteBody::new(
        inner,
        true, // is_sse: streaming
        "gemini",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        Arc::new(busbar_core::store::BreakerCfg::default()),
        "pa",
        Some(translate),
        Some(json_array),
        None,  // usage_sink
        false, // budget_spent
    );
    let out = fbb.into_body().collect().await.expect("drain").to_bytes();
    let text = String::from_utf8_lossy(&out);
    let arr: Value = serde_json::from_slice(&out).unwrap_or_else(|e| {
        panic!("client output must be a valid gemini JSON array: {e}; body={text}")
    });
    let prompt_tokens = arr.as_array().and_then(|els| {
        els.iter().find_map(|el| {
            el.get("usageMetadata")
                .and_then(|u| u.get("promptTokenCount"))
                .and_then(|v| v.as_i64())
        })
    });
    assert_eq!(
        prompt_tokens,
        Some(600),
        "the client's terminal usageMetadata must report the real prompt tokens (600), not 0/absent — body: {text}"
    );
}

/// CHARACTERIZATION, plain-SSE sibling: the terminal-usage fold must also deliver on the
/// PLAIN SSE path (no json-array framer), not just gemini json-array — the same defect class across the two
/// delivery paths. anthropic ingress / openai egress with include_usage: the client's terminal
/// `message_delta` must carry the real `usage.output_tokens` (400), not 0.
#[tokio::test]
async fn test_cross_protocol_stream_delivers_trailing_usage_anthropic_sse() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();

    let frames = [
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n",
        "data: [DONE]\n\n",
    ];
    let inner = futures::stream::iter(
        frames
            .iter()
            .map(|f| Ok::<Bytes, hyper::Error>(Bytes::from(f.as_bytes().to_vec())))
            .collect::<Vec<_>>(),
    );

    // Neutral seam: build the translator by NAME through the installed factory (as production
    // does); `is_sse = true` + ingress != egress reproduces the prior direct translator construction byte-for-byte.
    let translate =
        busbar_core::proto::new_stream_translator("anthropic", "openai", true).expect("translator");
    let fbb = FirstByteBody::new(
        inner,
        true,
        "anthropic",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        Arc::new(busbar_core::store::BreakerCfg::default()),
        "pa",
        Some(translate),
        None, // plain SSE — no json-array framer
        None,
        false,
    );
    let out = fbb.into_body().collect().await.expect("drain").to_bytes();
    let text = String::from_utf8_lossy(&out);
    // Find the terminal message_delta's usage.output_tokens in the anthropic SSE stream.
    let output_tokens = text.split("\n\n").find_map(|frame| {
        let data = frame.lines().find_map(|l| l.strip_prefix("data: "))?;
        let v: Value = serde_json::from_str(data).ok()?;
        if v.get("type").and_then(|t| t.as_str()) == Some("message_delta") {
            v.get("usage")
                .and_then(|u| u.get("output_tokens"))
                .and_then(|n| n.as_i64())
        } else {
            None
        }
    });
    assert_eq!(
        output_tokens,
        Some(400),
        "the anthropic terminal message_delta must report the real output_tokens (400), not 0 — body: {text}"
    );
}

/// An upstream TRANSPORT error mid-stream must NOT token-bill the partial usage accumulated
/// before the cut — symmetric with the terminal-error / translate-abort no-bill gates (every other
/// failure path suppresses or refunds). Drives the real FirstByteBody: an anthropic egress stream that
/// sets usage (100 input on message_start + 50 output on message_delta = 150 billable), then a real
/// reqwest transport Error. After the drop the gov must have charged ZERO. Pre-fix (no `stream_failed`
/// gate) the Drop billing site charged the 150 partial tokens = 15c.
#[tokio::test]
async fn test_mid_stream_transport_error_does_not_bill_partial_usage() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    // Spend is DERIVED now; the no-bill intent is asserted on the token ledger directly.
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("key");
    let charged_at: u64 = 1_700_000_000;
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "claude",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();

    // A real hyper transport error to inject AFTER the usage-bearing frames (mid-stream cut).
    let transport_err = hyper_transport_err().await;

    let frames: Vec<&str> = vec![
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"usage\":{\"input_tokens\":100,\"output_tokens\":0}}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":50}}\n\n",
    ];
    let mut items: Vec<Result<Bytes, hyper::Error>> = frames
        .iter()
        .map(|f| Ok(Bytes::from(f.as_bytes().to_vec())))
        .collect();
    items.push(Err(transport_err));
    let inner = Box::pin(futures::stream::iter(items));

    // Neutral seam: build the translator by NAME through the installed factory (as production
    // does); `is_sse = true` + ingress != egress reproduces the prior direct translator construction byte-for-byte.
    let translate =
        busbar_core::proto::new_stream_translator("openai", "anthropic", true).expect("translator");
    let fbb = FirstByteBody::new(
        inner,
        true, // is_sse
        "openai",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        Arc::new(busbar_core::store::BreakerCfg::default()),
        "pa",
        Some(translate),
        None,
        sink,
        false,
    );
    // Drain (emits the mid-stream error frame then None), then the body drops → Drop billing gate runs.
    let _ = fbb.into_body().collect().await;

    // Poll briefly: a pre-fix Drop would ledger the 150 partial tokens; the fixed gate records
    // nothing, so the token ledger stays 0.
    let mut tokens = 0;
    for _ in 0..150 {
        tokio::task::yield_now().await;
        tokens = gov
            .usage_for(&cost, &key.id, charged_at)
            .expect("usage read")
            .map(|u| u.tokens)
            .unwrap_or(0);
        if tokens != 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert_eq!(
        tokens, 0,
        "a mid-stream transport error must NOT bill the partial usage (pre-fix ledgered 150 tokens)"
    );
}

/// In `Passthrough` mode, a caller that
/// presents NO credential must fall back to an EMPTY credential, NOT the lane operator's
/// `api_key`. Borrowing the operator key would let an unauthenticated caller silently spend on the
/// operator's upstream account. With the empty-credential fallback the upstream returns its own
/// 401/403 (a client-auth fault attributed to the caller, no lane penalty). Drives the full
/// `forward_with_pool` passthrough path with `caller_token = None` against a misconfigured lane
/// that DOES carry a non-empty operator key, then asserts the UPSTREAM saw an empty Bearer
/// credential — NOT `Bearer sk-operator-secret` (the old borrow-the-operator-key behavior).
#[tokio::test]
async fn test_passthrough_no_caller_token_selects_empty_not_lane_key() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();

    // Upstream answers 200 so we can inspect the Authorization header it received.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-x",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}
            }),
        });
    let server = MockServer::new(state.clone()).await;

    // Passthrough mode + a MISCONFIGURED lane that DOES carry an operator key. Lane speaks OpenAI
    // (Bearer auth), ingress same-protocol openai.
    // 1.5.3: the credential MODE moved off `auth:` onto the `pools:` section, so the
    // open-front-door chain and the passthrough egress posture are now set independently.
    let app = TestApp::new()
        .upstream_creds(busbar_core::auth::UpstreamCreds::Passthrough)
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .api_key("sk-operator-secret"),
        )
        .pool("pa", &[(0, 1)])
        .build();

    let body = serde_json::to_vec(
        &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
    )
    .unwrap();
    // Caller presents NO credential.
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pa",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);

    // The upstream must NOT have received the operator key. With the fix the forwarded credential
    // is empty → `Authorization: Bearer ` (empty token); the OLD code forwarded
    // `Authorization: Bearer sk-operator-secret`, silently borrowing the operator key.
    let recorded_auth = state
        .get_last_auth_header()
        .expect("mock recorded an Authorization header");
    assert_ne!(
        recorded_auth, "Bearer sk-operator-secret",
        "passthrough with no caller credential must NOT borrow the operator's lane api_key"
    );
    assert!(
            !recorded_auth.contains("sk-operator-secret"),
            "operator key must never leak upstream for an unauthenticated passthrough caller; got {recorded_auth:?}"
        );
    // The forwarded credential is empty → a bare `Bearer` token (HTTP strips the trailing space of
    // the empty value on the wire), NOT `Bearer <operator-key>`.
    assert_eq!(
        recorded_auth.trim(),
        "Bearer",
        "passthrough with no caller credential must forward an EMPTY Bearer credential upstream"
    );

    server.shutdown().await;
}

/// Regression on the cross-protocol seam: a Bedrock backend returns an
/// identity-EMPTY non-stream IR (`read_response` yields `id`/`created`/`model` all `None`, since
/// a Converse body carries no body-level identity). On a Bedrock→Gemini hop the Gemini writer
/// gates `usageMetadata.totalTokenCount` and a synthesized `responseId` on the cross-protocol
/// BOUNDARY signal (`created.is_some() || model.is_some()`); before the seam stamped a synthesized
/// `created`, that signal never fired for Bedrock and a google-genai client read
/// `total_token_count`/`response_id` as ABSENT (a token-accounting gap + distinguishability tell).
/// This asserts both are now present on the translated Gemini body.
#[tokio::test]
async fn test_cross_protocol_bedrock_to_gemini_carries_total_tokens_and_response_id() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // Native AWS Converse (non-stream) 2xx: NO body-level id/created/model — only output,
    // stopReason, and usage. This is exactly the identity-empty shape the Bedrock reader returns.
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "Hi"}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 7, "outputTokens": 3}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    // Lane speaks Bedrock; ingress is Gemini → cross-protocol translation hop.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-bedrock",
                crate::proto_codec::PROTO_BEDROCK,
                &server.base_url(),
            )
            .provider("aws"),
        )
        .pool("pg", &[(0, 1)])
        .build();
    // Native Gemini generateContent (non-stream) request body.
    let body =
        serde_json::to_vec(&json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}))
            .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pg",
        None,
        "gemini",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "non-stream cross-protocol response uses the ingress (Gemini) JSON Content-Type"
    );
    use http_body_util::BodyExt as _;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    // totalTokenCount = promptTokenCount + candidatesTokenCount (7 + 3); a strict google-genai
    // client reads this for billing/accounting. Absent before the seam fix.
    assert_eq!(
        v["usageMetadata"]["totalTokenCount"],
        json!(10u64),
        "Bedrock→Gemini must carry usageMetadata.totalTokenCount; body: {v}"
    );
    assert_eq!(v["usageMetadata"]["promptTokenCount"], json!(7u64));
    assert_eq!(v["usageMetadata"]["candidatesTokenCount"], json!(3u64));
    // responseId is synthesized (Gemini-shaped, no foreign prefix) so the SDK's
    // GenerateContentResponse.response_id is always populated. Absent before the seam fix.
    let rid = v["responseId"].as_str().unwrap_or("");
    assert!(
        !rid.is_empty(),
        "Bedrock→Gemini must carry a synthesized responseId; body: {v}"
    );
    // No foreign-format identity leaked (Converse has none, but guard the contract anyway).
    let raw = String::from_utf8_lossy(&bytes);
    assert!(
        !raw.contains("chatcmpl-") && !raw.contains("msg_"),
        "no foreign-format id may appear in the Gemini body: {raw}"
    );
    server.shutdown().await;
}

/// The cross-protocol 2xx request-id attach: a Bedrock-INGRESS 2xx (non-stream, cross-protocol) must
/// carry `x-amzn-RequestId` — a real Converse response always does (the AWS SDK reads it via
/// `request_id()`); the error path already synthesizes it, this closes the SUCCESS gap.
#[tokio::test]
async fn test_bedrock_ingress_success_carries_amzn_request_id() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // OpenAI-shaped backend 2xx; ingress is bedrock → cross-protocol translation to Converse.
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-ok",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
            }),
        });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("pa", &[(0, 1)])
        .build();
    let body = serde_json::to_vec(
        &json!({"model": "pa", "messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
    )
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pa",
        None,
        "bedrock",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let amzn = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !amzn.is_empty(),
        "bedrock-ingress 2xx MUST carry a non-empty x-amzn-RequestId (matching a real Converse \
             response and the error path); got: {amzn:?}"
    );
    // UUID-v4 shaped: 36 chars, 8-4-4-4-12.
    assert_eq!(amzn.len(), 36, "x-amzn-RequestId is a UUID; got {amzn}");
    // The header must appear EXACTLY ONCE. The collapsed
    // maybe_attach_response_request_id was briefly called twice at this cross-protocol site,
    // appending two distinct x-amzn-RequestId values (axum `header()` appends). `.get()` masks it;
    // count all values.
    assert_eq!(
        resp.headers().get_all("x-amzn-requestid").iter().count(),
        1,
        "exactly ONE x-amzn-RequestId header (no duplicate from a double attach)"
    );
    server.shutdown().await;
}

/// On the relay paths, an anthropic-INGRESS 2xx must carry a
/// `request-id` RESPONSE HEADER — a real Anthropic response always does (the SDK reads it into
/// `Message._request_id`). On this CROSS-protocol hop (OpenAI backend → Anthropic client) there is
/// no upstream anthropic id to forward, so busbar must SYNTHESIZE a shape-correct `req_…` one.
#[tokio::test]
async fn test_anthropic_ingress_success_carries_request_id_header() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-ok",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
            }),
        });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("pa", &[(0, 1)])
        .build();
    let body = serde_json::to_vec(
        &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
    )
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pa",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let rid = resp
        .headers()
        .get("request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        rid.starts_with("req_"),
        "anthropic-ingress 2xx MUST carry a synthesized `request-id` header in the native req_ \
             shape; got {rid:?}"
    );
    // Exactly ONE `request-id` (no duplicate from a double attach).
    assert_eq!(
        resp.headers().get_all("request-id").iter().count(),
        1,
        "exactly ONE request-id header (no duplicate from a double attach)"
    );
    server.shutdown().await;
}

/// On the engine's STREAMING branch: an anthropic-
/// INGRESS STREAMING 2xx must ALSO carry the `request-id` response header. The non-streaming test
/// above exercises only the buffered builder; the streaming builder is a separate code path, so a
/// regression on the stream branch alone would otherwise pass CI. The official SDK reads
/// `request-id` into `Message._request_id` on streamed responses too — an absent header is a proxy
/// tell. Same-protocol anthropic stream (no upstream id supplied by the mock) → synthesized `req_`.
#[tokio::test]
async fn test_anthropic_ingress_streaming_carries_request_id_header() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // A minimal anthropic-shaped SSE stream (the mock serves `text/event-stream`, driving the
    // streaming branch). The header attachment is independent of the event payloads.
    state.push(MockResponse::Sse {
            events: vec![
                r#"event: message_start
data: {"type":"message_start","message":{"id":"msg_x","role":"assistant","content":[],"usage":{"input_tokens":3,"output_tokens":0}}}"#
                    .to_string(),
                r#"event: message_stop
data: {"type":"message_stop"}"#
                    .to_string(),
            ],
            abort_at_index: None,
        });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-x",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .provider("anthropic"),
        )
        .pool("ps", &[(0, 1)])
        .build();
    let body = serde_json::to_vec(&json!({
        "model": "ps",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 50,
        "stream": true
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "ps",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let rid = resp
        .headers()
        .get("request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        rid.starts_with("req_"),
        "anthropic-ingress STREAMING 2xx MUST carry a `request-id` header in the native req_ \
             shape (proxy engine maybe_attach_response_request_id path); got {rid:?}"
    );
    server.shutdown().await;
}

/// A cross-protocol CLIENT-fault 4xx must be RESHAPED into the ingress
/// protocol's native error envelope, not relayed with the EGRESS protocol's foreign error body.
/// An OpenAI backend returning a 400 with an OpenAI-shaped error must reach an Anthropic client as
/// the Anthropic error shape (`{"type":"error","error":{...}}`), with no OpenAI fields leaking.
#[tokio::test]
async fn test_cross_protocol_client_fault_reshapes_error_envelope() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // OpenAI-shaped 400 client-fault error body from the backend.
    state.push(MockResponse::Ok {
        status: StatusCode::BAD_REQUEST,
        body: json!({
            "error": {
                "message": "Invalid 'max_tokens': must be positive",
                "type": KIND_INVALID_REQUEST,
                "param": "max_tokens",
                "code": "invalid_value"
            }
        }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("pc", &[(0, 1)])
        .build();

    let body = serde_json::to_vec(
        &json!({"model": "pc", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
    )
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pc",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400, "client-fault status preserved");
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    use http_body_util::BodyExt as _;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    // Anthropic-native error envelope, NOT the OpenAI shape.
    assert_eq!(v["type"], "error", "Anthropic top-level error type");
    assert_eq!(v["error"]["type"], "invalid_request_error"); // golden wire-contract literal (kept bare on purpose)
    let raw = String::from_utf8_lossy(&bytes);
    assert!(
        !raw.contains("\"param\"") && !raw.contains("\"code\""),
        "OpenAI-specific error fields must not leak to an Anthropic client: {raw}"
    );
    // The human message is carried through.
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_tokens"),
        "upstream message surfaced: {v}"
    );
    server.shutdown().await;
}

/// A forward error path through the real `forward_with_pool` (empty candidate pool → exhaustion)
/// returns the ingress protocol's native JSON envelope with the right status.
#[tokio::test]
async fn test_forward_error_path_returns_native_envelope() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();
    let app = TestApp::new().build();
    // No candidates → "no usable lane" 503, shaped to the ingress (OpenAI) envelope.
    let resp = forward_with_pool(
        &app,
        vec![],
        serde_json::to_vec(&json!({"model": "x", "messages": []}))
            .unwrap()
            .into(),
        None,
        "missingpool",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 503, "no usable lane → 503");
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "forward error envelope is JSON, not text/plain"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        v.get("error").is_some(),
        "OpenAI-native error envelope has a top-level error object: {v}"
    );
}

/// The DEGRADED `forward_once` path (LeastBad/FallbackPool) must
/// NOT leak source-protocol-only passthrough keys onto a foreign backend. Both forward paths now
/// route request shaping through the single `translate_request_cross_protocol` seam (which clears
/// `ir.extra` before the egress writer), so the clear cannot be missing on one path. This drives
/// an OpenAI ingress request carrying `logprobs`/`top_logprobs`/`n` through `forward_once`
/// (lane in cooldown → LeastBad) to a mock ANTHROPIC lane and asserts none of those keys appear in
/// the egress body the backend actually received.
#[tokio::test]
async fn test_forward_once_cross_protocol_strips_source_only_extra_keys() {
    crate::testkit::install_test_seams();
    use busbar_core::store::now as store_now;
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // Anthropic-shaped 2xx so the degraded path serves a success (it relays the body verbatim;
    // we only care about what the backend RECEIVED, captured below).
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "msg_x",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "model": "claude-3",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 3, "output_tokens": 2}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    // Lane speaks ANTHROPIC; ingress is OpenAI → cross-protocol. Lane in long cooldown so normal
    // selection finds nothing and LeastBad serves via forward_once (the degraded path).
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-3",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .provider("anthropic")
            .cooldown_until(t0 + 600)
            .streak(3)
            .err(5),
        )
        .pool("leastbad", &[(0, 1)])
        .on_exhausted("leastbad", busbar_core::config::OnExhausted::LeastBad)
        .build();

    // `n: 1` (NOT >1) on purpose: this test is about EXTRA-KEY STRIPPING on the degraded path, not
    // about multiple candidates. A single-candidate `n` still exercises the "OpenAI-only `n` must not
    // leak onto an Anthropic backend" assertion below (the Anthropic writer omits `n` regardless of
    // value), while staying clear of the cross-protocol multi-candidate reject
    // (`translate_request_cross_protocol` rejects n>1, since the single-candidate IR would drop the
    // rest). Do NOT bump this above 1 — that would (correctly) turn this into a 400 and defeat the
    // 200-passthrough this test asserts.
    let req_body = serde_json::to_vec(&json!({
        "model": "leastbad",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16,
        "logprobs": true,
        "top_logprobs": 5,
        "n": 1
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "leastbad",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "LeastBad serves the 2xx");

    // The egress body the Anthropic backend ACTUALLY received: the OpenAI-only passthrough keys
    // must be absent (cleared at the shared translate seam), proving the degraded path no longer
    // diverges from the hot path.
    let egress = state
        .get_last_request_body()
        .expect("backend received a request body");
    let ev: Value = serde_json::from_slice(&egress).expect("egress body is JSON");
    let obj = ev.as_object().expect("egress body is an object");
    assert!(
        !obj.contains_key("logprobs"),
        "forward_once must NOT leak OpenAI `logprobs` onto an Anthropic backend: {ev}"
    );
    assert!(
        !obj.contains_key("top_logprobs"),
        "forward_once must NOT leak OpenAI `top_logprobs`: {ev}"
    );
    assert!(
        !obj.contains_key("n"),
        "forward_once must NOT leak OpenAI `n`: {ev}"
    );
    // Modeled fields still translated across.
    assert!(obj.contains_key("messages"), "messages translated: {ev}");
    server.shutdown().await;
}

/// The `forward_once` degraded
/// (LeastBad/FallbackPool) cross-protocol path must apply the SAME tool-id native remap the main
/// forward path does. Before the fix it stripped identity + stamped `created` but omitted
/// `ToolIdRemap::remap_response`, so a tool-call response emitted the egress backend's RAW native
/// id (an Anthropic `toolu_…`) verbatim to an OpenAI client — a foreign-format proxy tell and a
/// broken tool round-trip. Assert the client sees an OpenAI-native `call_…` id, never the raw one.
#[tokio::test]
async fn test_forward_once_cross_protocol_remaps_tool_call_id() {
    crate::testkit::install_test_seams();
    use busbar_core::store::now as store_now;
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // Anthropic backend returns a tool_use response carrying a native anthropic tool id.
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "msg_x",
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "tool_use",
                "id": "toolu_origRAW123",
                "name": "get_weather",
                "input": {"city": "SF"}
            }],
            "model": "claude-3",
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 3, "output_tokens": 2}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    // Lane speaks ANTHROPIC; ingress OpenAI → cross-protocol; lane in cooldown so LeastBad serves
    // via the degraded forward_once path.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-3",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .provider("anthropic")
            .cooldown_until(t0 + 600)
            .streak(3)
            .err(5),
        )
        .pool("leastbad", &[(0, 1)])
        .on_exhausted("leastbad", busbar_core::config::OnExhausted::LeastBad)
        .build();

    let req_body = serde_json::to_vec(&json!({
        "model": "leastbad",
        "messages": [{"role": "user", "content": "weather?"}],
        "max_tokens": 16
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        req_body.into(),
        None,
        "leastbad",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "LeastBad serves the 2xx");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read response body");
    let v: Value = serde_json::from_slice(&body).expect("client body is JSON");
    // OpenAI ingress → the tool call id lives at choices[0].message.tool_calls[0].id.
    let tool_id = v
        .pointer("/choices/0/message/tool_calls/0/id")
        .and_then(|s| s.as_str())
        .unwrap_or_else(|| panic!("expected an OpenAI tool_calls id in: {v}"));
    assert!(
        tool_id.starts_with("call_"),
        "tool id must be remapped to the OpenAI-native `call_` shape, got {tool_id}"
    );
    assert_ne!(
        tool_id, "toolu_origRAW123",
        "the raw Anthropic egress tool id must NOT leak verbatim to the OpenAI client"
    );
    assert!(
        !body
            .windows("toolu_origRAW123".len())
            .any(|w| w == b"toolu_origRAW123"),
        "the raw Anthropic tool id must not appear anywhere in the client response"
    );
    server.shutdown().await;
}

/// The `forward_once` degraded
/// (LeastBad/FallbackPool) SAME-protocol Bedrock error relay must forward BOTH `x-amzn-requestid`
/// and `x-amzn-errortype` verbatim, mirroring the main path. Before the fix it captured neither on
/// this path — a native AWS SDK's `request_id()` would return None and typed-exception dispatch
/// would fall back from header-first to body `__type`, both detectable tells.
#[tokio::test]
async fn test_forward_once_bedrock_error_relays_amzn_headers() {
    crate::testkit::install_test_seams();
    use busbar_core::store::now as store_now;
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // A native Bedrock error carries x-amzn-requestid + x-amzn-errortype response headers.
    state.push(MockResponse::ServerErrorWithHeaders {
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: json!({"message": "service unavailable", "__type": "ServiceUnavailableException"}),
        headers: vec![
            ("x-amzn-requestid", "amzn-req-id-XYZ789"),
            ("x-amzn-errortype", "ServiceUnavailableException"),
        ],
    });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    // Bedrock lane, same-protocol bedrock ingress. The lane points at /v1/messages (a route the
    // mock answers) — the same-protocol relay under test keys off the upstream response, not the
    // URL. Cooled down so LeastBad serves via the degraded forward_once path.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-3",
                crate::proto_codec::PROTO_BEDROCK,
                &server.base_url(),
            )
            .provider("aws")
            .path("/v1/messages")
            .cooldown_until(t0 + 600)
            .streak(3)
            .err(5),
        )
        .pool("leastbad", &[(0, 1)])
        .on_exhausted("leastbad", busbar_core::config::OnExhausted::LeastBad)
        .build();

    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        serde_json::to_vec(&json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}))
            .unwrap()
            .into(),
        None,
        "leastbad",
        None,
        "bedrock",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 503, "upstream 503 relayed verbatim");
    // Both x-amzn headers must be present on the relayed response, verbatim.
    let headers = resp.headers();
    assert_eq!(
        headers
            .get("x-amzn-requestid")
            .and_then(|v| v.to_str().ok()),
        Some("amzn-req-id-XYZ789"),
        "x-amzn-requestid must be relayed verbatim on the degraded same-protocol bedrock path"
    );
    assert_eq!(
        headers
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("ServiceUnavailableException"),
        "x-amzn-errortype must be relayed verbatim (was dropped entirely before the fix)"
    );
    // Body relayed verbatim too.
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        body.windows(b"__type".len()).any(|w| w == b"__type"),
        "native bedrock error body relayed verbatim"
    );
    server.shutdown().await;
}

/// Same-protocol (anthropic ingress → anthropic backend) error relay must forward the upstream's
/// `request-id` response header VERBATIM — not synthesize a fresh `req_…` — and attach it EXACTLY
/// ONCE. Guards `forward_with_pool`'s same-proto error relay (the
/// `maybe_attach_response_request_id(upstream)` branch): the SDK reads this into `APIError.request_id`,
/// so a synthesized id (or a duplicated header from a double-attach) is a proxy tell. The exact-once
/// assertion guards the axum `header()`-APPENDS double-attach failure mode.
#[tokio::test]
async fn test_anthropic_same_proto_error_relays_upstream_request_id_verbatim_once() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // A native Anthropic 4xx carries a `request-id` response header; the same-proto relay must
    // forward it verbatim.
    state.push(MockResponse::ServerErrorWithHeaders {
        status: StatusCode::BAD_REQUEST,
        body: json!({
            "type": "error",
            "error": {"type": KIND_INVALID_REQUEST, "message": "bad request"}
        }),
        headers: vec![("request-id", "upstream-anthropic-rid-0001")],
    });
    let server = MockServer::new(state.clone()).await;

    // Anthropic lane, same-protocol anthropic ingress (no cross-protocol reshape).
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-3",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .provider("anthropic"),
        )
        .pool("pa", &[(0, 1)])
        .build();

    let resp = forward_with_pool(
            &app,
            vec![crate::engine::WeightedLane {
                idx: 0,
                weight: 1,
                attempt_timeout_ms: None,
                reasoning: None,
            }],
            serde_json::to_vec(
                &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
            )
            .unwrap()
            .into(),
            None,
            "pa",
            None,
            "anthropic",
            crate::test_support::CHAT, None,
        )
        .await;

    assert_eq!(resp.status().as_u16(), 400, "upstream 400 relayed");
    // The upstream request-id is forwarded VERBATIM (not a synthesized `req_…`).
    let ids: Vec<&str> = resp
        .headers()
        .get_all("request-id")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "request-id must be attached EXACTLY once (axum header() APPENDS), got {ids:?}"
    );
    assert_eq!(
        ids[0], "upstream-anthropic-rid-0001",
        "the upstream request-id must be relayed verbatim, not synthesized"
    );
    server.shutdown().await;
}

/// Same-protocol PASSTHROUGH-mode 401/403 relay (the `is_passthrough_40x` branch of
/// `forward_with_pool`) must forward the upstream's `request-id` response header VERBATIM — not
/// synthesize a fresh `req_…` — and attach it EXACTLY ONCE. This is the passthrough-auth sibling
/// of `test_anthropic_same_proto_error_relays_upstream_request_id_verbatim_once` (which exercises
/// the ClientFault 400 path): a caller-key 401 carries no breaker penalty and is relayed via the
/// `maybe_attach_response_request_id(upstream)` call, so a synthesized id (or a duplicated header
/// from a double-attach) is a proxy tell the SDK's `APIError.request_id` would surface.
#[tokio::test]
async fn test_anthropic_same_proto_passthrough_401_relays_request_id_verbatim_once() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // A native Anthropic 401 carries a `request-id` response header; the same-proto passthrough
    // relay must forward it verbatim.
    state.push(MockResponse::ServerErrorWithHeaders {
        status: StatusCode::UNAUTHORIZED,
        body: json!({
            "type": "error",
            "error": {"type": KIND_AUTHENTICATION, "message": "invalid x-api-key"}
        }),
        headers: vec![("request-id", "upstream-rid-passthrough")],
    });
    let server = MockServer::new(state.clone()).await;

    // Passthrough auth mode + anthropic lane, same-protocol anthropic ingress.
    // 1.5.3: the credential MODE moved off `auth:` onto the `pools:` section, so the
    // open-front-door chain and the passthrough egress posture are now set independently.
    let app = TestApp::new()
        .upstream_creds(busbar_core::auth::UpstreamCreds::Passthrough)
        .lane(
            LaneSpec::new(
                "claude-3",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .provider("anthropic"),
        )
        .pool("pa", &[(0, 1)])
        .build();

    let resp = forward_with_pool(
            &app,
            vec![crate::engine::WeightedLane {
                idx: 0,
                weight: 1,
                attempt_timeout_ms: None,
                reasoning: None,
            }],
            serde_json::to_vec(
                &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
            )
            .unwrap()
            .into(),
            None,
            "pa",
            None,
            "anthropic",
            crate::test_support::CHAT, None,
        )
        .await;

    assert_eq!(
        resp.status().as_u16(),
        401,
        "passthrough upstream 401 relayed verbatim"
    );
    // The upstream request-id is forwarded VERBATIM (not a synthesized `req_…`), exactly once.
    assert_eq!(
        resp.headers().get_all("request-id").iter().count(),
        1,
        "request-id must be attached EXACTLY once (axum header() APPENDS)"
    );
    assert_eq!(
        resp.headers()
            .get("request-id")
            .and_then(|v| v.to_str().ok()),
        Some("upstream-rid-passthrough"),
        "the upstream request-id must be relayed verbatim, not synthesized"
    );
    server.shutdown().await;
}

/// At every engine error site: no forward-layer error body returned to a client
/// may begin with the wire-visible internal `router:` prefix — a deterministic proxy tell no native
/// endpoint emits. The route-layer regression test never reaches the forward layer; this drives the
/// most-exercised forward-layer error surfaces (overload 503 via empty-pool exhaustion, and the
/// Status503 retry body) for every ingress protocol and asserts the body is free of `router:`.
#[tokio::test]
async fn test_forward_layer_errors_carry_no_router_prefix() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();
    for ingress in [
        "openai",
        "anthropic",
        "gemini",
        "cohere",
        "responses",
        "bedrock",
    ] {
        let app = TestApp::new().build();
        // Empty candidate pool → "no usable lane" / Status503 overload 503 through the forward
        // layer (forward_with_pool → handle_exhaustion_for_pool → handle_status_503).
        let resp = forward_with_pool(
            &app,
            vec![],
            serde_json::to_vec(&json!({"model": "x", "messages": []}))
                .unwrap()
                .into(),
            None,
            "missingpool",
            None,
            ingress,
            crate::test_support::CHAT,
            None,
        )
        .await;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains("router:"),
            "forward-layer error body for ingress {ingress} (status {status}) leaked the \
                 `router:` tell: {body}"
        );
    }
}

/// A native AWS SDK ConverseStream request answered
/// by a buffered (non-SSE) `application/json` 2xx from a CROSS-protocol OpenAI lane must be emitted
/// at the HTTP boundary as `application/vnd.amazon.eventstream`, decode into the native frame
/// sequence, AND carry a UUID `x-amzn-RequestId`. The existing coverage tests only the synthesis
/// fn directly; this asserts the response-builder wiring (CT, frames, amzn id) on a real Response.
#[tokio::test]
async fn test_bedrock_converse_stream_buffered_cross_protocol_emits_binary_eventstream() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // NON-SSE buffered OpenAI 2xx (no SSE) to a cross-protocol bedrock-ingress ConverseStream.
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-buf",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
            }),
        });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "glm-4.5",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("zai"),
        )
        .pool("pb", &[(0, 1)])
        .build();
    // `stream: true` → bedrock ConverseStream intent; cross-protocol to an OpenAI lane that
    // answers with a buffered (non-SSE) body → bedrock_response_to_eventstream synthesis path.
    let body = serde_json::to_vec(&json!({
        "model": "pb",
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "stream": true
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pb",
        None,
        "bedrock",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    // (a) Content-Type is the native binary eventstream CT.
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/vnd.amazon.eventstream"),
        "buffered cross-protocol ConverseStream must be the native binary CT, not application/json"
    );
    // (c) UUID-v4 x-amzn-RequestId present.
    let amzn = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(amzn.len(), 36, "x-amzn-RequestId is a UUID; got {amzn:?}");
    // (b) body decodes into the native frame sequence.
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let mut buf = bytes.to_vec();
    let frames = busbar_substrate::eventstream::drain_frames(&mut buf);
    let names: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(names.first(), Some(&"messageStart"), "frames: {names:?}");
    assert!(names.contains(&"contentBlockDelta"), "frames: {names:?}");
    assert!(names.contains(&"messageStop"), "frames: {names:?}");
    assert!(names.contains(&"metadata"), "frames: {names:?}");
    server.shutdown().await;
}

/// In `forward_with_pool_parsed_inner`:
/// `client_include_usage` (`wants_stream && <client body opted into stream_options.include_usage>`)
/// gates whether Busbar force-injects `stream_options.include_usage:true` onto the OUTGOING OpenAI
/// egress request (`&& !client_include_usage` at the injection site): an AND, not an OR.
/// Under the `||` mutant, `wants_stream` ALONE would make `client_include_usage` true for every
/// streaming request, so this injection would be wrongly SKIPPED for the common case (a client
/// that streams but never mentions `stream_options`) — busbar would then bill the completion at
/// ZERO tokens, since the upstream never emits the trailing usage chunk without the opt-in. Assert
/// the real, currently-mandatory injection actually happens on the wire.
#[tokio::test]
async fn test_streaming_openai_egress_without_client_opt_in_still_gets_include_usage_injected() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events: vec![
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"},"finish_reason":null}]}"#
                .to_string(),
            r#"data: {"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#
                .to_string(),
            "data: [DONE]".to_string(),
        ],
        abort_at_index: None,
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("openai"),
        )
        .pool("po", &[(0, 1)])
        .build();
    // Same-protocol OpenAI stream; the client body carries NO `stream_options` at all — the common
    // case `client_include_usage` must read `false` for.
    let body = serde_json::to_vec(&json!({
        "model": "po",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "po",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let egress = state
        .get_last_request_body()
        .expect("backend received a request body");
    let ev: Value = serde_json::from_slice(&egress).expect("egress body is JSON");
    assert_eq!(
        ev.pointer("/stream_options/include_usage"),
        Some(&Value::Bool(true)),
        "busbar must force stream_options.include_usage on the outgoing OpenAI stream request \
             even when the client didn't opt in (or billing sees zero tokens): {ev}"
    );
    server.shutdown().await;
}

/// The gemini JSON-array buffered-synthesis branch in
/// `forward_with_pool`): a native Gemini `:streamGenerateContent` WITHOUT `?alt=sse` routed
/// cross-protocol to an OpenAI lane that answers with a BUFFERED (non-SSE) 2xx must emit a
/// one-element JSON ARRAY (`[{...}]`) of native `GenerateContentResponse` under
/// `application/json` — NOT a bare `{...}` object (undecodable by a Gemini SDK parsing a
/// non-alt=sse streaming body as an array) and NOT SSE. Mirrors the bedrock buffered test above;
/// the SSE-backend tests only exercise the live `GeminiJsonArrayFramer`, never this branch.
#[tokio::test]
async fn test_gemini_json_array_buffered_cross_protocol_emits_one_element_array() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-buf",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "gpt-4o",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
            }),
        });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("openai"),
        )
        .pool("pg", &[(0, 1)])
        .build();
    // Gemini ingress `:streamGenerateContent` (no alt=sse): the route injects `stream:true` and
    // the JSON-array shim key. Cross-protocol to an OpenAI lane that answers buffered (non-SSE).
    let body = serde_json::to_vec(&json!({
        "model": "pg",
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "stream": true,
        (busbar_core::proto::array_stream_shim_key_for(crate::proto_codec::PROTO_GEMINI).expect("gemini declares an array-stream shim key")): true
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pg",
        None,
        "gemini",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    // (a) Content-Type is application/json (the native non-alt=sse streaming CT).
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "buffered gemini JSON-array stream must be application/json"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&bytes).expect("body must be JSON");
    // (b) body parses as a JSON ARRAY, (c) with exactly one element.
    let arr = parsed.as_array().expect("body must be a JSON array");
    assert_eq!(arr.len(), 1, "exactly one element; got {parsed}");
    // (d) the element is a native GenerateContentResponse carrying `candidates`, with no OpenAI
    // `choices` leak.
    let el = &arr[0];
    assert!(
        el.get("candidates").is_some(),
        "element must be a native GenerateContentResponse with `candidates`; got {el}"
    );
    assert!(
        el.get("choices").is_none(),
        "no OpenAI `choices` may leak to a Gemini client; got {el}"
    );
    server.shutdown().await;
}

/// The gemini JSON-array buffered-synthesis branch in `forward_once`,
/// the FallbackPool/exhaustion path): the SECOND copy of the branch must match the primary path.
/// Drive a gemini `:streamGenerateContent` (no alt=sse) through the degraded `forward_once` route
/// (lane parked in long cooldown + LeastBad on_exhausted, as in
/// `test_forward_once_cross_protocol_strips_source_only_extra_keys`) to a buffered cross-protocol
/// backend, and assert the same one-element JSON array under `application/json`.
#[tokio::test]
async fn test_gemini_json_array_buffered_via_forward_once_matches_primary() {
    crate::testkit::install_test_seams();
    use busbar_core::store::now as store_now;
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-buf2",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "gpt-4o",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
            }),
        });
    let server = MockServer::new(state.clone()).await;
    let t0 = store_now();
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("openai")
            .cooldown_until(t0 + 600)
            .streak(3)
            .err(5),
        )
        .pool("leastbad-g", &[(0, 1)])
        .on_exhausted("leastbad-g", busbar_core::config::OnExhausted::LeastBad)
        .build();
    let body = serde_json::to_vec(&json!({
        "model": "leastbad-g",
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "stream": true,
        (busbar_core::proto::array_stream_shim_key_for(crate::proto_codec::PROTO_GEMINI).expect("gemini declares an array-stream shim key")): true
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "leastbad-g",
        None,
        "gemini",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "LeastBad serves via forward_once"
    );
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "forward_once buffered gemini JSON-array stream must be application/json"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&bytes).expect("body must be JSON");
    let arr = parsed.as_array().expect("body must be a JSON array");
    assert_eq!(arr.len(), 1, "exactly one element; got {parsed}");
    let el = &arr[0];
    assert!(
        el.get("candidates").is_some(),
        "forward_once element must carry native `candidates`; got {el}"
    );
    assert!(
        el.get("choices").is_none(),
        "no OpenAI `choices` may leak via forward_once; got {el}"
    );
    server.shutdown().await;
}

/// `record_nonstream_usage` vs the `ReadEnd::Truncated` guard:
/// CHOSEN SEMANTICS — a cross-protocol non-stream success body that exceeds OUR translation cap
/// (`MAX_TRANSLATED_BODY_BYTES`, 32 MiB) is UNTRANSLATABLE: the client receives HTTP 500 with NO
/// completion, so token usage is NOT charged (the `record_nonstream_usage` call now lives AFTER
/// the Truncated guard, consistent with the TransportError branch which also charges nothing for
/// an undelivered body). The breaker success recorded on the 2xx headers stands (this is our cap,
/// not an upstream fault) and the budget is NOT refunded. This test pins the client-visible
/// outcome: an over-cap cross-protocol non-stream body returns the ingress-native 500 rather than
/// being translated and delivered (which is what would let its tokens be charged).
#[tokio::test]
async fn test_cross_protocol_nonstream_over_cap_body_returns_500_uncharged() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    // Serialize against sibling tests that mutate the process-global `limits::INSTALLED`, and pin a
    // small KNOWN cap under an RAII guard so the body below is deterministically over-cap regardless
    // of a concurrent install (restored on drop). Without the lock this test READS the cap to size
    // `huge`, and a sibling install could move it mid-run.
    let _lock = busbar_core::limits::LIMITS_TEST_LOCK.lock().await;
    const CAP: usize = 4096;
    let _limits_guard = busbar_core::limits::InstallGuard::install(
        &busbar_core::config::LimitsResolved::with_request_body_max_bytes(CAP),
    );
    assert_eq!(super::max_translated_body_bytes(), CAP);
    let state = Arc::new(MockServerState::new());
    // An OpenAI chat.completion whose `content` alone is > CAP, so the whole body overruns the
    // installed translate cap and `read_capped` reports ReadEnd::Truncated.
    let huge = "x".repeat(CAP + 1024);
    state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-huge",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "gpt-4o",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": huge}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 999999}
            }),
        });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("openai"),
        )
        .pool("pc", &[(0, 1)])
        .build();
    // Anthropic ingress, non-stream, cross-protocol to the OpenAI lane → buffered translate path.
    let body = serde_json::to_vec(&json!({
        "model": "pc",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pc",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    // The over-cap body is untranslatable → ingress-native 500, NOT a translated 2xx (which is the
    // only path that would charge the body's usage tokens).
    assert_eq!(
        resp.status().as_u16(),
        500,
        "an over-cap cross-protocol non-stream body must return 500, not a charged 2xx"
    );
    server.shutdown().await;
}

/// REGRESSION guard: the
/// `ReadEnd::Truncated` arm is a DELIBERATE no-refund policy — the upstream genuinely succeeded, so
/// the lane DID serve a request and the budget unit must NOT be returned even though the client
/// gets a 500. Pins that the guard's `disarm()` before this branch's `return` preserves that policy
/// (a refund-by-default guard would invert it).
#[tokio::test]
async fn test_truncated_body_does_not_refund_budget() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    // Serialize against the sibling tests that mutate the process-global `limits::INSTALLED`
    // (`InstallGuard::install` / `install`) — this test READS the translate-body cap to build an
    // over-cap body, and a sibling's install landing mid-run would move the cap out from under it.
    // Install a small KNOWN cap under an RAII guard so the body is deterministically over-cap
    // (restored on drop). See the correctly-locked sibling `..._over_cap_body_still_bills_tail_usage`.
    let _lock = busbar_core::limits::LIMITS_TEST_LOCK.lock().await;
    const CAP: usize = 4096;
    let _limits_guard = busbar_core::limits::InstallGuard::install(
        &busbar_core::config::LimitsResolved::with_request_body_max_bytes(CAP),
    );
    assert_eq!(super::max_translated_body_bytes(), CAP);
    let state = Arc::new(MockServerState::new());
    let huge = "x".repeat(CAP + 1024);
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "chatcmpl-huge",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": huge}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 999999}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("openai")
            .budget(1),
        )
        .pool("pc", &[(0, 1)])
        .build();
    assert_eq!(app.store.lane_budget_remaining(0), Some(1));
    let body = serde_json::to_vec(&json!({
        "model": "pc",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pc",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 500);
    assert_eq!(
        app.store.lane_budget_remaining(0),
        Some(0),
        "an over-cap (Truncated) body is OUR cap, not an upstream fault, so the headers-time \
             spend must NOT be refunded"
    );
    server.shutdown().await;
}

/// `read_capped` now pre-reserves a bounded initial buffer capacity
/// to cut the per-chunk reallocation churn as the buffer grows toward `cap`. The pre-reserve must
/// NOT change cap ENFORCEMENT: a body that exceeds `cap` is still rejected — the returned buffer
/// holds exactly `cap` bytes (the admitted prefix) and the end reason is `ReadEnd::Truncated`,
/// never `Complete`. This test serves a body well over a small cap and asserts the cap is enforced
/// to the byte. (Guards against a future pre-reserve regression that mistakenly admitted up to the
/// reserved capacity rather than `cap`.)
#[tokio::test]
async fn test_read_capped_enforces_cap_exactly_and_reports_truncated() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // A 64 KiB raw JSON-string body — far larger than the 1 KiB cap used below.
    let big = "y".repeat(64 * 1024);
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!(big),
    });
    let server = MockServer::new(state.clone()).await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/messages", server.base_url()))
        .send()
        .await
        .expect("mock GET must succeed");

    const CAP: usize = 1024;
    let (bytes, end) = read_capped(resp.bytes_stream(), CAP).await;
    assert_eq!(
        bytes.len(),
        CAP,
        "read_capped must admit EXACTLY cap bytes for an over-cap body, never more"
    );
    assert_eq!(
        end,
        ReadEnd::Truncated,
        "an over-cap body must report Truncated, not Complete"
    );
    server.shutdown().await;
}

/// The client-facing 400 body for an unparseable JSON request
/// must carry ONLY the generic, vendor-plausible message — never serde_json's Display detail
/// (line/column/expectation), which is a busbar-internal tell and can echo fragments of the
/// malformed body. Sends a body that is valid UTF-8 but invalid JSON containing a recognizable
/// sentinel, and asserts neither the serde phrasing nor the sentinel appears on the wire. Fails
/// against any version that interpolates `{e}` into the response body.
#[tokio::test]
async fn test_unparseable_json_400_carries_no_serde_internals() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1", // never reached: parse fails before any egress
        ))
        .pool("p", &[(0, 1)])
        .build();
    // Valid UTF-8, invalid JSON. The sentinel would surface in serde_json's Display
    // ("expected value at line 1 column N", echoing nearby bytes) if it were interpolated.
    let bad = br#"{ "model": "p", BUSBAR_SENTINEL_LEAK }"#.to_vec();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        bad.into(),
        None,
        "p",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "unparseable JSON must be a 400"
    );
    use http_body_util::BodyExt as _;
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("We could not parse the JSON body of your request."),
        "400 body must carry the generic message; got {text}"
    );
    assert!(
        !text.contains("BUSBAR_SENTINEL_LEAK"),
        "400 body must NOT echo bytes from the malformed request; got {text}"
    );
    for needle in ["line 1", "column", "expected", "at line"] {
        assert!(
            !text.contains(needle),
            "400 body must NOT leak serde_json Display internals ({needle:?}); got {text}"
        );
    }
}

/// On the STREAMING (`is_sse`) path the 2xx headers
/// already spent one `max_requests` budget unit, but a PRE-FIRST-BYTE upstream body transport
/// failure delivers no usable response. The buffered `ReadEnd::TransportError` paths refund that
/// unit; a streaming path that refunds NOTHING permanently drains one serving-capacity unit on
/// every streaming transport failure. `FirstByteBody`'s pre-first-byte error arm must refund
/// symmetrically (guarded by `budget_spent`).
#[tokio::test]
async fn test_streaming_pre_first_byte_transport_error_refunds_budget() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::store::{BreakerCfg, BreakerState, TripConfig, TripMode};
    use bytes::Bytes;
    use futures::StreamExt as _;

    // Lane 0: budget-limited with a single remaining unit.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "m",
                crate::proto_codec::PROTO_ANTHROPIC,
                "http://127.0.0.1:1",
            )
            .budget(1),
        )
        .pool("p", &[(0, 1)])
        .build();

    // Spend the one unit, exactly as the 2xx-headers path does before streaming. The budget is
    // now 0 and `budget_spent` is true.
    let budget_spent = app.store.spend_budget(0);
    assert!(budget_spent, "the headers-spend must decrement the unit");
    assert!(
        !app.store.spend_budget(0),
        "budget is exhausted after the single unit is spent (no refund yet)"
    );

    // A REAL `hyper::Error` transport cut. This stands in for the pre-first-byte failure shape
    // the streaming body sees when the upstream socket dies before any byte reaches the client.
    let reqwest_err = hyper_transport_err().await;

    // The inner upstream stream yields ONLY that error — no byte ever reaches the client, so this
    // exercises the pre-first-byte (`else`) arm, not the mid-stream arm. `Box::pin` makes the
    // one-shot stream `Unpin`, which `FirstByteBody`'s `Stream` impl requires of its inner.
    let inner = Box::pin(futures::stream::once(async move {
        Err::<Bytes, hyper::Error>(reqwest_err)
    }));
    // The 2xx headers recorded an optimistic breaker SUCCESS; simulate that so the pre-first-byte
    // failure below has something to reverse. A consecutive n:1 trip config makes one
    // recorded transient observable as Closed→Open.
    app.store.record_success_in("p", 0);
    let breaker_cfg = std::sync::Arc::new(BreakerCfg {
        trip: TripConfig {
            mode: TripMode::Consecutive,
            consecutive_n: 1,
            ..TripConfig::default()
        },
        ..BreakerCfg::default()
    });
    assert!(
        matches!(app.store.breaker_state_in("p", 0), BreakerState::Closed),
        "precondition: the pool cell is Closed after the optimistic success"
    );

    let body = FirstByteBody::new(
        inner,
        true, // is_sse: streaming path
        "anthropic",
        crate::test_support::CHAT,
        (), // permit: a unit placeholder is sufficient for the Stream bounds
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        breaker_cfg,
        "p",
        None,
        None,
        None,
        budget_spent,
    );
    futures::pin_mut!(body);

    // First poll surfaces the generic transport error item (the body terminates on it).
    let first = body.next().await;
    assert!(
        matches!(first, Some(Err(_))),
        "pre-first-byte transport failure must terminate the body with an error item"
    );

    // The compensating refund must have restored the unit: a fresh spend now succeeds. Without
    // the fix the budget stays at 0 and this spend returns false.
    assert!(
        app.store.spend_budget(0),
        "streaming pre-first-byte transport failure must refund the spent budget unit"
    );

    // The pre-first-byte transport failure must ALSO record a breaker transient, reversing
    // the optimistic 2xx success and tripping the cell Closed→Open. Before the fix the transient
    // was gated on `had_first` and this stayed Closed - a lane that always fails before the first
    // byte would never trip.
    assert!(
        matches!(
            app.store.breaker_state_in("p", 0),
            BreakerState::Open { .. }
        ),
        "pre-first-byte transport failure must record a breaker transient"
    );
}

/// A lane whose upstream connects and returns 2xx headers but then dies BEFORE
/// the first streamed byte on EVERY attempt must still trip its circuit breaker. Each pre-first-byte
/// transport failure now records a breaker transient (no longer gated on `had_first`), so REPEATED
/// pre-first-byte failures accumulate toward the trip threshold instead of silently recording
/// nothing. This drives a cell to Open after the configured number of consecutive pre-first-byte
/// failures. (Isolating the transient count - no intervening headers-success - so the consecutive
/// streak reflects exactly the pre-first-byte failures: the point is that they ARE counted at all,
/// which before the fix they were not.)
#[tokio::test]
async fn test_repeated_pre_first_byte_failures_trip_breaker() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::store::{BreakerCfg, BreakerState, TripConfig, TripMode};
    use bytes::Bytes;
    use futures::StreamExt as _;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://127.0.0.1:1",
        ))
        .pool("p", &[(0, 1)])
        .build();

    // Trip only after 3 consecutive failures, so we can watch the cell stay Closed for the first
    // two pre-first-byte failures and flip to Open on the third - proving each one is counted.
    let breaker_cfg = std::sync::Arc::new(BreakerCfg {
        trip: TripConfig {
            mode: TripMode::Consecutive,
            consecutive_n: 3,
            ..TripConfig::default()
        },
        ..BreakerCfg::default()
    });

    for attempt in 1..=3u32 {
        // The upstream dies before the first byte. A fresh transport-cut error is the pre-first-
        // byte failure shape.
        let reqwest_err = hyper_transport_err().await;
        let inner = Box::pin(futures::stream::once(async move {
            Err::<Bytes, hyper::Error>(reqwest_err)
        }));
        let body = FirstByteBody::new(
            inner,
            true, // is_sse
            "anthropic",
            crate::test_support::CHAT,
            (),
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
            app.clone(),
            0,
            breaker_cfg.clone(),
            "p",
            None,
            None,
            None,
            false, // no budget spent on this unlimited lane
        );
        futures::pin_mut!(body);
        let item = body.next().await;
        assert!(
            matches!(item, Some(Err(_))),
            "attempt {attempt}: pre-first-byte failure terminates the body with an error"
        );

        if attempt < 3 {
            assert!(
                matches!(app.store.breaker_state_in("p", 0), BreakerState::Closed),
                "attempt {attempt}: below the threshold the cell stays Closed but the failure is \
                 counted"
            );
        } else {
            assert!(
                matches!(
                    app.store.breaker_state_in("p", 0),
                    BreakerState::Open { .. }
                ),
                "the 3rd consecutive pre-first-byte failure must trip the breaker Closed→Open"
            );
        }
    }
}

/// On a NON-SSE same-protocol passthrough (e.g.
/// OpenAI→OpenAI `/chat/completions`, content-type `application/json`) the 2xx headers recorded
/// an optimistic breaker SUCCESS, but a mid-BODY transport failure AFTER the first byte delivers
/// an incomplete response. `FirstByteBody`'s non-SSE `else` arm previously refunded budget but
/// NEVER recorded a compensating transient (the SSE if-branch and BOTH buffered
/// `ReadEnd::TransportError` paths do) — so repeated mid-body failures accumulated as successes
/// and the lane never tripped. The arm must now record a transient (gated on `had_first`),
/// mirroring the SSE/buffered paths. With a consecutive `n: 1` trip config, one mid-body failure
/// must drive the cell Closed→Open; before the fix it stays Closed (no transient recorded).
#[tokio::test]
async fn test_streaming_nonsse_mid_body_transport_error_records_transient() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::store::{BreakerCfg, BreakerState, TripConfig, TripMode};
    use bytes::Bytes;
    use futures::StreamExt as _;

    // Lane 0: OpenAI, budget-limited with a single remaining unit (matches the 2xx-headers spend).
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto_codec::PROTO_OPENAI, "http://127.0.0.1:1").budget(1))
        .pool("p", &[(0, 1)])
        .build();

    // Spend the one unit exactly as the 2xx-headers path does before streaming.
    let budget_spent = app.store.spend_budget(0);
    assert!(budget_spent, "the headers-spend must decrement the unit");

    // Trip config that opens the cell on a SINGLE consecutive failure, so one recorded transient
    // is observable as a Closed→Open transition (and the absence of one leaves it Closed).
    let breaker_cfg = std::sync::Arc::new(BreakerCfg {
        trip: TripConfig {
            mode: TripMode::Consecutive,
            consecutive_n: 1,
            ..TripConfig::default()
        },
        ..BreakerCfg::default()
    });

    // The pool cell starts Closed.
    assert!(
        matches!(app.store.breaker_state_in("p", 0), BreakerState::Closed),
        "pool cell must start Closed before any mid-body failure"
    );

    // A REAL `hyper::Error` transport cut — the mid-body failure shape the body sees after the
    // first byte already streamed.
    let reqwest_err = hyper_transport_err().await;

    // Inner stream yields one GOOD chunk (sets `first_byte_sent`) THEN the transport error — this
    // exercises the post-first-byte (`had_first == true`) NON-SSE `else` arm. `Box::pin` makes the
    // stream `Unpin`, which `FirstByteBody`'s `Stream` impl requires of its inner.
    let inner = Box::pin(futures::stream::iter(vec![
        Ok::<Bytes, hyper::Error>(Bytes::from_static(b"{\"id\":\"x\",")),
        Err::<Bytes, hyper::Error>(reqwest_err),
    ]));
    let body = FirstByteBody::new(
        inner,
        false, // is_sse: NON-streaming same-protocol passthrough (application/json)
        "openai",
        crate::test_support::CHAT,
        (), // permit placeholder
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        breaker_cfg,
        "p",
        None,
        None,
        None,
        budget_spent,
    );
    futures::pin_mut!(body);

    // First poll: the good chunk passes through (and marks the first byte sent).
    let first = body.next().await;
    assert!(
        matches!(first, Some(Ok(_))),
        "the first chunk must stream through before the mid-body failure"
    );

    // Second poll: the mid-body transport failure terminates the body with a generic error item.
    let second = body.next().await;
    assert!(
        matches!(second, Some(Err(_))),
        "post-first-byte transport failure must terminate the body with an error item"
    );

    // The compensating transient must have driven the cell Closed→Open. Without the fix no
    // transient is recorded and the cell stays Closed (the incomplete delivery is mis-counted as
    // the optimistic 2xx-headers success).
    assert!(
        matches!(
            app.store.breaker_state_in("p", 0),
            BreakerState::Open { .. }
        ),
        "non-SSE mid-body transport failure must record a transient (cell trips Open), \
             not stand as the optimistic success"
    );

    // The budget-refund block is unchanged: the spent unit is still refunded on this failed
    // delivery, so a fresh spend succeeds.
    assert!(
        app.store.spend_budget(0),
        "non-SSE mid-body transport failure must still refund the spent budget unit"
    );
}

/// A CROSS-PROTOCOL
/// stream whose translator ABORTS after the first byte — its reassembly buffer overran
/// `MAX_BUF` (>16MiB without a frame terminator) or it hit a malformed egress prelude — sets NO
/// `tap.terminal_error` (no in-band `{"type":"error"}` frame was ever scanned). A
/// `Poll::Ready(None)` arm that reverses the optimistic 2xx breaker success ONLY on `terminal_error`
/// misses the translate-abort SIBLING, and therefore (a) records the
/// optimistic success un-reversed (cell stays Closed) AND (b) billed the partial captured tokens
/// via `record_tokens`. After the fix BOTH gates treat `terminal_error.is_some() ||
/// translate.aborted()` as failed: the cell trips Closed→Open AND no token fee is charged.
#[tokio::test]
async fn test_streaming_translate_abort_trips_breaker_and_skips_billing() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    use busbar_core::store::{BreakerCfg, BreakerState, TripConfig, TripMode};
    use bytes::Bytes;
    use futures::StreamExt as _;

    // Lane 0: OpenAI EGRESS. The cross-protocol seam is anthropic INGRESS ← openai EGRESS, so a
    // translator is constructed by name (ingress != egress → Some).
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("p", &[(0, 1)])
        .build();

    // Trip config: open the cell on a SINGLE consecutive failure, so the one compensating
    // transient this arm must record is observable as a Closed→Open transition (and its absence
    // leaves the cell Closed — the un-reversed optimistic success the bug records).
    let breaker_cfg = Arc::new(BreakerCfg {
        trip: TripConfig {
            mode: TripMode::Consecutive,
            consecutive_n: 1,
            ..TripConfig::default()
        },
        ..BreakerCfg::default()
    });

    // The pool cell starts Closed (the synchronous 2xx-headers success was already recorded
    // before streaming; this arm must REVERSE it on the translate abort).
    assert!(
        matches!(app.store.breaker_state_in("p", 0), BreakerState::Closed),
        "pool cell must start Closed before the translate abort"
    );

    // A usage sink over a real GovState: any accrual call with nonzero tokens leaves an
    // observable token ledger in the key's window (spend derives; tokens are the ledger).
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let charged_at: u64 = 1_700_000_000;
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            charged_at,
        )
        .expect("create key");
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    // Cross-protocol translator: openai EGRESS SSE → anthropic INGRESS SSE. The tap scans the
    // translated anthropic output for usage.
    // Neutral seam: build the translator by NAME through the installed factory (as production
    // does); `is_sse = true` + ingress != egress reproduces the prior direct translator construction byte-for-byte.
    let translate = busbar_core::proto::new_stream_translator("anthropic", "openai", true)
        .expect("anthropic<-openai translate must construct");

    // Inner upstream stream:
    //   chunk 1: an OpenAI trailing usage-only chunk (`include_usage` convention) carrying
    //            prompt_tokens — translated to an anthropic `message_delta` whose usage the tap
    //            reads, giving a NONZERO captured input_tokens (the partial tokens the bug bills).
    //            This also marks `first_byte_sent`.
    //   chunk 2: a >MAX_BUF run of bytes with NO SSE frame terminator → the translate's
    //            reassembly buffer overflows and `abort()` fires (aborted == true), with NO
    //            terminal-error frame ever scanned (tap.terminal_error stays None).
    // Then the inner stream ends with `None`, driving the `Poll::Ready(None)` arm under test.
    let usage_chunk =
        b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n"
            .to_vec();
    let overflow = vec![b'x'; busbar_substrate::eventstream::MAX_FRAME_BYTES + 16];
    let inner = Box::pin(futures::stream::iter(vec![
        Ok::<Bytes, hyper::Error>(Bytes::from(usage_chunk)),
        Ok::<Bytes, hyper::Error>(Bytes::from(overflow)),
    ]));

    let body = FirstByteBody::new(
        inner,
        true, // is_sse: streaming cross-protocol path
        "anthropic",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        app.clone(),
        0,
        breaker_cfg,
        "p",
        Some(translate),
        None,
        sink,
        false, // budget_spent: irrelevant to this arm
    );
    futures::pin_mut!(body);

    // Drain the body to completion (the abort produces no client error item — it is a silent
    // truncation on the wire; the observable effects are breaker + billing).
    while let Some(item) = body.next().await {
        // Translated/terminator bytes may flow; none of them is an Err for this arm.
        let _ = item;
    }

    // (1) BREAKER: the translate abort must have recorded a compensating transient that drove the
    // cell Closed→Open. Before the fix no transient is recorded (only `terminal_error` was
    // checked) and the optimistic 2xx success stands → the cell stays Closed.
    assert!(
        matches!(
            app.store.breaker_state_in("p", 0),
            BreakerState::Open { .. }
        ),
        "a cross-protocol translate abort after first byte must record a breaker transient \
             (cell Closed→Open), not stand as the optimistic 2xx success"
    );

    // (2) BILLING: a captured-nonzero-token aborted stream must NOT be token-billed. The old
    // code's accrual of the captured 1000 tokens would show in the key's window ledger; the fix
    // skips the call entirely, so the window stays at 0 tokens.
    let ledgered = gov
        .usage_for(&cost, &key.id, charged_at)
        .expect("usage read")
        .map(|u| u.tokens)
        .unwrap_or(0);
    assert_eq!(
        ledgered, 0,
        "an aborted cross-protocol stream must NOT charge a token fee \
             (record_usage must not be called)"
    );
}

/// A client that disconnects MID-STREAM (drops the body before
/// the natural `Poll::Ready(None)` end) must still have the tokens generated+delivered so far
/// billed — via `impl Drop for FirstByteBody`. Drives a CLEAN cross-protocol stream (no abort, no
/// terminal error), polls it ONCE so the usage chunk is consumed (usage tapped, `usage_sink` still
/// `Some`), then DROPS the body without draining to `None`. The Drop path must charge the captured
/// tokens. (The no-bill-on-abort/terminal-error branch shares the SAME predicate as the tested
/// `Poll::Ready(None)` gate; the no-double-bill on clean completion is guaranteed by `usage_sink.take()`.)
#[tokio::test]
async fn test_cancel_drop_bills_partial_tokens() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    use busbar_core::store::BreakerCfg;
    use bytes::Bytes;
    use futures::StreamExt as _;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("p", &[(0, 1)])
        .build();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    // Spend derives; token-billing intent is asserted on the token ledger.
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let charged_at: u64 = 1_700_000_000;
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            charged_at,
        )
        .expect("create key");
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    // Neutral seam: build the translator by NAME through the installed factory (as production
    // does); `is_sse = true` + ingress != egress reproduces the prior direct translator construction byte-for-byte.
    let translate = busbar_core::proto::new_stream_translator("anthropic", "openai", true)
        .expect("anthropic<-openai translate");
    // A single OpenAI trailing usage-only chunk → translated anthropic message_delta whose usage
    // the tap reads (1000 billable tokens). NO overflow (no abort), NO error frame.
    let usage_chunk =
        b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n"
            .to_vec();
    let inner = Box::pin(futures::stream::iter(vec![Ok::<Bytes, hyper::Error>(
        Bytes::from(usage_chunk),
    )]));

    // Build, poll ONCE (consumes the usage chunk; usage_sink stays Some because Poll::Ready(None)
    // is never reached), then drop the body inside this block → Drop fires on the mid-stream cancel.
    {
        let body = FirstByteBody::new(
            inner,
            true,
            "anthropic",
            crate::test_support::CHAT,
            (),
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
            app.clone(),
            0,
            Arc::new(BreakerCfg::default()),
            "p",
            Some(translate),
            None,
            sink,
            false,
        );
        futures::pin_mut!(body);
        let _ = body.next().await; // poll once: feed the usage chunk, accumulate IrUsage
                                   // body dropped here (cancel before stream end) → Drop bills the captured tokens.
    }

    // The Drop's accrual may land off this task; drain it with a bounded poll.
    let mut ledgered = 0;
    for _ in 0..200 {
        ledgered = gov
            .usage_for(&cost, &key.id, charged_at)
            .expect("usage read")
            .map(|u| u.tokens)
            .unwrap_or(0);
        if ledgered > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        ledgered, 1000,
        "a mid-stream-cancelled stream must bill the captured tokens via Drop \
             (600 input + 400 output = 1000 tokens ledgered)"
    );
}

/// INVERSE of `test_cancel_drop_bills_partial_tokens`: the Drop path must SKIP billing when the
/// cross-protocol translate ABORTED (e.g. a reassembly-buffer overflow) before the drop, even
/// though usage was captured. Feed a usage chunk (usage accumulates) THEN an overflow chunk
/// (`> MAX_FRAME_BYTES`, no SSE terminator → `translate.aborted()` trips), poll those two chunks
/// but NOT to `Poll::Ready(None)` (so `usage_sink` stays `Some`), then DROP the body. The Drop's
/// `aborted()` guard (mirroring the `Poll::Ready(None)` no-bill-on-failure gate) must suppress
/// the charge → the key's spend stays 0.
#[tokio::test]
async fn test_cancel_drop_skips_billing_on_aborted_translate() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
    use busbar_core::store::BreakerCfg;
    use bytes::Bytes;
    use futures::StreamExt as _;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("p", &[(0, 1)])
        .build();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    // Spend derives; token-billing intent is asserted on the token ledger.
    let cost = Arc::new(busbar_core::cost::CostModel::flat(0));
    let charged_at: u64 = 1_700_000_000;
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            charged_at,
        )
        .expect("create key");
    let sink = Some(UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: std::sync::Arc::new(key.clone()),
        pool: std::sync::Arc::from(""),
        charged_at,
        admit: None,
    });

    // Neutral seam: build the translator by NAME through the installed factory (as production
    // does); `is_sse = true` + ingress != egress reproduces the prior direct translator construction byte-for-byte.
    let translate = busbar_core::proto::new_stream_translator("anthropic", "openai", true)
        .expect("anthropic<-openai translate");
    // chunk 1: usage-only OpenAI chunk → translated anthropic usage the tap captures (nonzero).
    // chunk 2: a >MAX_FRAME_BYTES run with NO SSE terminator → translate buffer overflows and
    //          `abort()` fires (`aborted() == true`). NO terminal-error frame.
    let usage_chunk =
        b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n"
            .to_vec();
    let overflow = vec![b'x'; busbar_substrate::eventstream::MAX_FRAME_BYTES + 16];
    let inner = Box::pin(futures::stream::iter(vec![
        Ok::<Bytes, hyper::Error>(Bytes::from(usage_chunk)),
        Ok::<Bytes, hyper::Error>(Bytes::from(overflow)),
    ]));

    // Build, poll the TWO chunks (usage accumulates, then the overflow trips `aborted()`) but do
    // NOT poll to `None` — so `usage_sink` stays `Some` and the drop exercises the Drop path with
    // an aborted translate.
    {
        let body = FirstByteBody::new(
            inner,
            true,
            "anthropic",
            crate::test_support::CHAT,
            (),
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
            app.clone(),
            0,
            Arc::new(BreakerCfg::default()),
            "p",
            Some(translate),
            None,
            sink,
            false,
        );
        futures::pin_mut!(body);
        let _ = body.next().await; // usage chunk → accumulate IrUsage
        let _ = body.next().await; // overflow chunk → translate.abort() trips aborted()
                                   // body dropped here → Drop's aborted() guard must skip billing.
    }

    // Give any (erroneous) deferred accrual a chance to land, then confirm the ledger is still 0.
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    let ledgered = gov
        .usage_for(&cost, &key.id, charged_at)
        .expect("usage read")
        .map(|u| u.tokens)
        .unwrap_or(0);
    assert_eq!(
        ledgered, 0,
        "a mid-stream drop after a translate ABORT must NOT bill (the Drop's aborted() guard \
             suppresses the charge), inverse of test_cancel_drop_bills_partial_tokens"
    );
}

/// Cancellation must refund the headers-time `spend_budget` unit. Unlike
/// `test_streaming_pre_first_byte_transport_error_refunds_budget` (a TERMINAL error arm, which
/// refunds in the poll arm and sets `ended`), this drops the body mid-stream WITHOUT ever reaching
/// a terminal poll arm — the shape a client disconnect or LB reset produces. A `Drop` that does not
/// read `budget_spent` loses the unit forever.
#[tokio::test]
async fn test_cancel_drop_mid_stream_refunds_budget() {
    crate::testkit::install_test_seams();
    use super::FirstByteBody;
    use busbar_core::store::BreakerCfg;
    use bytes::Bytes;
    use futures::StreamExt as _;

    // Lane 0: budget-limited with a single remaining unit.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "m",
                crate::proto_codec::PROTO_ANTHROPIC,
                "http://127.0.0.1:1",
            )
            .budget(1),
        )
        .pool("p", &[(0, 1)])
        .build();

    // Spend the one unit, exactly as the 2xx-headers path does before streaming.
    let budget_spent = app.store.spend_budget(0);
    assert!(budget_spent, "the headers-spend must decrement the unit");
    assert_eq!(app.store.lane_budget_remaining(0), Some(0));

    // A normal in-band SSE chunk (no error, no terminator) — the stream never reaches a terminal
    // poll arm before it is dropped, mirroring a client disconnect mid-response.
    let chunk = b"data: {\"type\":\"content_block_delta\"}\n\n".to_vec();
    let inner = Box::pin(futures::stream::iter(vec![Ok::<Bytes, hyper::Error>(
        Bytes::from(chunk),
    )]));

    {
        let body = FirstByteBody::new(
            inner,
            true, // is_sse
            "anthropic",
            crate::test_support::CHAT,
            (),
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
            app.clone(),
            0,
            Arc::new(BreakerCfg::default()),
            "p",
            None,
            None,
            None,
            budget_spent,
        );
        futures::pin_mut!(body);
        let _ = body.next().await; // poll once: consume the chunk, no terminal arm reached
                                   // body dropped here (cancel before stream end) → must refund.
    }

    assert_eq!(
        app.store.lane_budget_remaining(0),
        Some(1),
        "a mid-stream cancel must refund the headers-time spend_budget unit"
    );
}

/// In `translate_response_cross_protocol`: the
/// gemini JSON-array wrap (`if gemini_json_array && wants_stream`) is gated on BOTH conditions,
/// not just `wants_stream` alone (an AND, not an OR). `test_gemini_json_array_buffered_
/// cross_protocol_emits_one_element_array` above proves the TRUE&&TRUE case (gemini ingress,
/// stream shim present); this proves the far more common divergent case an `||` mutant would
/// wrongly array-wrap: a NON-gemini streaming ingress (`gemini_json_array` is always false here —
/// `uses_array_stream_shim()` is gemini-only) whose upstream answers buffered (non-SSE), which
/// must fall through to the plain single-object response every non-Gemini client expects.
#[tokio::test]
async fn test_non_gemini_stream_buffered_cross_protocol_stays_a_plain_object_not_an_array() {
    crate::testkit::install_test_seams();
    use http_body_util::BodyExt as _;
    busbar_core::metrics::init();
    let state = Arc::new(MockServerState::new());
    // NON-SSE buffered anthropic 2xx to a cross-protocol OpenAI-ingress streaming request.
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({
            "id": "msg_buf",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hi"}],
            "model": "claude-3",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 7, "output_tokens": 3}
        }),
    });
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-3",
                crate::proto_codec::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .provider("anthropic"),
        )
        .pool("pn", &[(0, 1)])
        .build();
    // OpenAI ingress, `stream: true`, NO gemini shim key — gemini_json_array must be false
    // regardless (OpenAI's writer doesn't implement `uses_array_stream_shim`).
    let body = serde_json::to_vec(&json!({
        "model": "pn",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "pn",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "buffered cross-protocol non-stream fallback is application/json"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&bytes).expect("body must be JSON");
    assert!(
        parsed.is_object(),
        "an `||` mutant would wrongly array-wrap this non-gemini buffered response: {parsed}"
    );
    assert!(
        parsed.get("choices").is_some(),
        "must be a native OpenAI chat-completion object: {parsed}"
    );
    server.shutdown().await;
}
