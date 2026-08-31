// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/handlers/anthropic.rs`.

use super::*;

/// Anthropic serves chat only: `operation_handler` must answer `Some` for `Chat` and `None`
/// for every other operation (the standard no-handler 404 path) — enumerated so a future
/// `Operation` variant added here without a matching registry arm is a compile error, not a
/// silent 404.
#[test]
fn operation_handler_serves_chat_only() {
    let h = AnthropicRequestHandler;
    assert!(h.operation_handler(Operation::CHAT).is_some());
    for op in [
        Operation::EMBEDDINGS,
        Operation::MODERATION,
        Operation::IMAGE,
        Operation::TRANSCRIPTION,
        Operation::SPEECH,
        Operation::RERANK,
    ] {
        assert!(
            h.operation_handler(op).is_none(),
            "{op:?} must have no handler on the Anthropic protocol"
        );
    }
}

/// A request path ending in `/v1/messages` resolves to `Chat`; anything else resolves to
/// `None` (no-handler 404) — the body is never consulted (Anthropic names the operation in the
/// path only). Zero coverage of this before — a path-string typo or an inverted `ends_with`
/// would have passed every existing test.
#[test]
fn resolve_operation_matches_the_messages_path_only() {
    let h = AnthropicRequestHandler;
    assert_eq!(
        h.resolve_operation("/v1/messages", b""),
        Some(Operation::CHAT)
    );
    // A mounted-prefix path still matches via `ends_with`.
    assert_eq!(
        h.resolve_operation("/proxy/upstream/v1/messages", b""),
        Some(Operation::CHAT)
    );
    // Unrelated / sibling paths (including near-misses and the Vertex egress shape, which is
    // never what ingress sees) must NOT resolve.
    for path in [
        "/v1/chat/completions",
        "/v1/complete",
        "/v1/messages/extra",
        "/v1/message",
        "/v1/projects/p/locations/us-central1/publishers/anthropic/models/claude:rawPredict",
        "",
    ] {
        assert_eq!(
            h.resolve_operation(path, b""),
            None,
            "path '{path}' must not resolve to any operation"
        );
    }
}

#[test]
fn path_base_uses_vertex_rawpredict_with_model_in_url() {
    let h = AnthropicRequestHandler;
    let model = "claude-3-5-sonnet";
    let ctx = |stream, path_base| EgressCtx {
        operation: Operation::CHAT,
        model,
        stream,
        path_base,
    };
    // Native Anthropic: static Messages path, model rides the body.
    assert_eq!(h.upstream_path(&ctx(false, None)), "/v1/messages");
    // Claude-on-Vertex: model moves into the URL via `:rawPredict`.
    let vbase = "/v1/projects/p/locations/us-central1/publishers/anthropic/models";
    assert_eq!(
            h.upstream_path(&ctx(false, Some(vbase))),
            "/v1/projects/p/locations/us-central1/publishers/anthropic/models/claude-3-5-sonnet:rawPredict"
        );
    // Streaming → `:streamRawPredict`.
    assert_eq!(
            h.upstream_path(&ctx(true, Some(vbase))),
            "/v1/projects/p/locations/us-central1/publishers/anthropic/models/claude-3-5-sonnet:streamRawPredict"
        );
}
