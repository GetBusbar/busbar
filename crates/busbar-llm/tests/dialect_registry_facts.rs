// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM DIALECTS' REGISTRY FACTS — relocated from core's own `#[cfg(test)]` binary (1.6.0 Phase
//! 4, batch 60 S10 residue). Core's test binary now registers a neutral SYNTHETIC protocol set and
//! names no plane crate; a test whose assertion is a real dialect's fact (which protocols ship, which
//! verbs they serve, the chat cell's reads, a dialect's native error envelope and headers, the shipped
//! provider catalog's protocols) lives with the plane that owns those dialects. Bodies are unchanged
//! except for `crate::` → `busbar_kernel::` paths and the registrations each test installs first.

use busbar_kernel::handlers::request_handler;
use busbar_kernel::operation::Operation;
use busbar_kernel::proto::{
    PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_COHERE, PROTO_GEMINI, PROTO_OPENAI, PROTO_RESPONSES,
};
use std::collections::HashMap;

/// This plane's registrations, installed into the kernel's process registries (the same four
/// `tests/auth_native_envelope.rs` installs; an integration target links the library without
/// `testkit`).
fn install_llm_registrations() {
    busbar_kernel::proto::register_test_protocols(busbar_llm::DECLS);
    busbar_kernel::plane::registry::register_test_plane(&LLM_PLANE);
    busbar_kernel::ingress::arrival::set_test_path_ingress(|| busbar_llm::PATH_INGRESS);
    busbar_kernel::ingress::arrival::set_test_body_ingress(|| busbar_llm::BODY_INGRESS);
}

/// A deployment with NO plane mounted: every path resolves through the resolver's residual arm,
/// which is the arm these vendor-envelope assertions are about.
fn residual_planes() -> busbar_kernel::plane::PlaneDispatch {
    busbar_kernel::plane::PlaneDispatch::default()
}

// ── from core's src/handlers/tests/registry_tests.rs ─────────────────────────────────────────────

#[test]
fn registry_resolves_openai_and_its_moderation_handler() {
    install_llm_registrations();
    let h = request_handler(PROTO_OPENAI).expect("the shipped protocol's handler is registered");
    assert_eq!(h.protocol_name(), PROTO_OPENAI);
    assert!(h.operation_handler(Operation::MODERATION).is_some());
    assert!(
        request_handler("zzz-unknown").is_none(),
        "unknown protocol → None"
    );
}

#[test]
fn every_protocol_serves_chat_via_its_request_handler() {
    install_llm_registrations();
    // Chat is operation #1, reached through the SAME registry as every other op. All six
    // protocols resolve a handler and a chat OperationHandler — the unified dispatch, no special path.
    for proto in [
        PROTO_OPENAI,
        PROTO_ANTHROPIC,
        PROTO_GEMINI,
        PROTO_BEDROCK,
        PROTO_COHERE,
        PROTO_RESPONSES,
    ] {
        let h = request_handler(proto).expect("protocol registered");
        assert!(
            h.operation_handler(Operation::CHAT).is_some(),
            "{proto} must serve chat via operation_handler(Chat)"
        );
    }
}

// ── from core's src/handlers/tests/dispatch_tests.rs ─────────────────────────────────────────────

#[test]
fn chat_declares_its_capabilities() {
    install_llm_registrations();
    // The chat cell as production resolves it — `(protocol, Chat)` through the registry, framed on
    // HTTP — rather than a hand-built const over the plugin's handler type.
    let chat = busbar_kernel::handlers::op_for(
        busbar_kernel::proto::PROTO_OPENAI,
        Operation::CHAT,
        busbar_kernel::transport::Transport::Http,
    )
    .expect("the shipped protocol serves chat");
    assert_eq!(chat.name(), "chat");
    assert!(chat.streaming(), "chat streams");
    assert!(
        chat.taps_nonstream_usage(),
        "chat bills tokens from the body"
    );
    assert!(
        chat.wants_stream(&serde_json::json!({"stream": true})),
        "chat reads the stream boolean"
    );
    assert!(!chat.wants_stream(&serde_json::json!({})));
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": "you are helpful"})),
        Some("you are helpful")
    );
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": ""})),
        None
    );
}

// ── from core's src/config/tests/tests.rs ────────────────────────────────────────────────────────

/// The shipped providers.yaml catalog must parse, name only known protocols, and use HTTPS.
#[test]
fn test_shipped_providers_catalog_valid() {
    install_llm_registrations();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml");
    let raw = std::fs::read_to_string(path).expect("read providers.yaml");
    let defs: HashMap<String, busbar_kernel::config::ProviderDef> =
        serde_yaml::from_str(&raw).expect("parse providers.yaml");
    assert!(defs.len() >= 10, "catalog should be non-trivial");
    for (name, def) in &defs {
        assert!(
            // Neutral registry seam: a protocol is KNOWN iff it has a registered declaration
            // (`decl_for`), reached without naming the witnessed codec (`protocol_for`).
            busbar_kernel::proto::decl_for(&def.protocol).is_some(),
            "provider '{name}' names unknown protocol '{}'",
            def.protocol
        );
        assert!(
            def.base_url.starts_with("https://"),
            "provider '{name}' base_url must be https"
        );
    }
}

// ── from core's src/tests/tests.rs ───────────────────────────────────────────────────────────────

/// A 404 fallback on a Bedrock path must carry the native `__type` envelope AND the `x-amzn-*`
/// headers a real AWS endpoint always emits — never axum's empty body (a proxy tell).
#[test]
fn test_fallback_bedrock_404_is_native_envelope_with_amzn_headers() {
    install_llm_registrations();
    let resp = busbar_kernel::router::fallback_error_response(
        &residual_planes(),
        "/model/some.model/converse",
        axum::http::StatusCode::NOT_FOUND,
        busbar_kernel::proto::ERR_TYPE_NOT_FOUND,
        "missing",
    );
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json"), // golden wire-contract literal (kept bare on purpose)
        "fallback must be application/json, not bare text"
    );
    assert!(
        resp.headers().get("x-amzn-requestid").is_some(),
        "a Converse-path fallback must carry x-amzn-RequestId"
    );
    assert!(
        resp.headers().get("x-amzn-errortype").is_some(),
        "a Converse-path fallback must carry x-amzn-errortype"
    );
}

/// The body-limit 413 on a Converse path is reshaped into Bedrock's native envelope with its
/// `x-amzn-*` headers. Core's `reshape_oversized_413` is crate-private, so the relocated test drives
/// the SAME reshape where production runs it: a real oversized POST through the live layer stack
/// (`build_router_with_limits` with a tiny body cap). The assertions are the original's.
#[tokio::test]
async fn test_oversized_body_413_bedrock_native_envelope_with_amzn_headers() {
    install_llm_registrations();
    busbar_kernel::metrics::init();
    let app = busbar_kernel::test_support::TestApp::new().build();
    let (router, _handle) = busbar_kernel::router::build_router_with_limits(app, 64, 1024, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let reshaped = reqwest::Client::new()
        .post(format!("http://{addr}/model/some.model/converse"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "pad": "x".repeat(4096) }).to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(reshaped.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        reshaped
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json") // golden wire-contract literal (kept bare on purpose)
    );
    assert!(
        reshaped.headers().get("x-amzn-requestid").is_some(),
        "a Converse-path 413 must carry x-amzn-RequestId"
    );
    assert!(
        reshaped.headers().get("x-amzn-errortype").is_some(),
        "a Converse-path 413 must carry x-amzn-errortype"
    );
    let bytes = reshaped.bytes().await.unwrap();
    server.abort();
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("reshaped Converse-path 413 body must be valid JSON");
    assert!(
        v.get("__type").is_some(),
        "a Converse-path 413 must carry the native __type envelope; got {v}"
    );
}

/// The llm plane's registry row, assembled kernel-side from its contract declaration
/// and its behaviour table.
static LLM_PLANE: busbar_kernel::plane::registry::PlaneDecl =
    busbar_kernel::plane::registry::PlaneDecl::assemble(
        busbar_llm::PLANE_DECLARATION,
        busbar_llm::PLANE_HOOKS,
    );
