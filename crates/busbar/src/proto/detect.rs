// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ingress Router: DUMB protocol identification.
//! `(path, headers)` → which protocol dialect the client is speaking — that is the Router's ENTIRE
//! job. Which OPERATION the request asks for is the chosen `RequestHandler`'s decision
//! (`resolve_operation(path, body)` — it may need the body; the Router never sees one). Returns
//! `None` for non-protocol paths (health, admin, unknown) — those keep their explicit routes.
//!
//! Adding a protocol touches exactly three places: an ID line here, a `RequestHandler`, and its
//! `OperationHandler` cells. Nothing else.
//!
//! NB: this is `router` (protocol identification), distinct from `routing` (load-balancing policy).

use axum::http::HeaderMap;

use crate::proto::{
    PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_COHERE, PROTO_GEMINI, PROTO_OPENAI, PROTO_RESPONSES,
};

/// The ingress protocol. Ladder (order load-bearing): mandatory-unique auth header → Gemini path
/// verb → path discriminator. A `(path, header)` pattern claimed by two protocols must be a registry
/// error at load time (enforced elsewhere), never a silent first-match.
pub(crate) fn protocol_id(path: &str, h: &HeaderMap) -> Option<&'static str> {
    // 1. mandatory-unique auth headers (unambiguous regardless of path)
    if h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256"))
    {
        return Some(PROTO_BEDROCK);
    }
    if h.contains_key("anthropic-version") || h.contains_key("anthropic-beta") {
        return Some(PROTO_ANTHROPIC);
    }
    if h.contains_key("x-goog-api-key") {
        return Some(PROTO_GEMINI);
    }
    // `x-api-key` is Anthropic's credential header and, among the six registered protocols, unique to
    // it (Gemini uses x-goog-api-key; Azure-style is `api-key`). Catches curl users who omit the
    // anthropic-version header.
    if h.contains_key("x-api-key") {
        return Some(PROTO_ANTHROPIC);
    }
    // 2. Gemini path verb (key in ?key=, no header)
    if path.contains(":generateContent")
        || path.contains(":streamGenerateContent")
        || path.contains(":embedContent")
        || path.contains(":batchEmbedContents")
        || path.contains(":predict")
    {
        return Some(PROTO_GEMINI);
    }
    // 2b. The Gemini models wildcard surface: everything under `/v1{,beta}/models/{rest}` goes to the
    // gemini ARM even when the action is unknown or absent — that arm owns the ambiguity envelopes
    // (a colon-less `/v1/models/{id}` is an OpenAI `model.retrieve`; an unknown `:action` gets the
    // native Gemini unsupported-action error). Mirrors the pre-collapse wildcard routes exactly.
    if path.starts_with("/v1/models/") || path.starts_with("/v1beta/models/") {
        return Some(PROTO_GEMINI);
    }
    // 3. path discriminator (bearer trio + everyone else)
    if path.ends_with("/v1/chat/completions") {
        return Some(PROTO_OPENAI);
    }
    if path.ends_with("/v2/chat") || path.ends_with("/v1/chat") {
        return Some(PROTO_COHERE);
    }
    if path.ends_with("/v2/embed") || path.ends_with("/v2/rerank") {
        return Some(PROTO_COHERE);
    }
    if path.ends_with("/v1/responses") {
        return Some(PROTO_RESPONSES);
    }
    if path.contains("/v1/messages") {
        return Some(PROTO_ANTHROPIC);
    }
    if path.contains("/converse") {
        return Some(PROTO_BEDROCK);
    }
    if path.starts_with("/model/") && path.ends_with("/invoke") {
        return Some(PROTO_BEDROCK);
    }
    // OpenAI-family JSON/audio/image ops
    if path.ends_with("/v1/embeddings")
        || path.ends_with("/v1/moderations")
        || path.contains("/v1/images/")
        || path.contains("/v1/audio/")
    {
        return Some(PROTO_OPENAI);
    }
    None
}

// NOTE: operation resolution deliberately does NOT live here. The Router identifies the protocol;
// the chosen `RequestHandler::resolve_operation(path, body)` decides the operation (it may need the
// body — Gemini's generateContent and Bedrock's InvokeModel are body-disambiguated).

#[cfg(test)]
#[path = "tests/detect_tests.rs"]
mod tests;
