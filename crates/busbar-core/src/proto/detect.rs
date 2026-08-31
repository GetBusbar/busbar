// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ingress Router: DUMB protocol identification.
//! `(path, headers)` → which protocol dialect the client is speaking — that is the Router's ENTIRE
//! job. Which OPERATION the request asks for is the chosen `RequestHandler`'s decision
//! (`resolve_operation(path, body)` — it may need the body; the Router never sees one). Returns
//! `None` for non-protocol paths (health, admin, unknown) — those keep their explicit routes.
//!
//! ## The ladder is DATA now, and it lives with the protocols
//!
//! This once held a hand-ordered `if`-ladder that named every dialect (`anthropic-version` →
//! anthropic, `AWS4-HMAC-SHA256` → bedrock, …). That ladder was the single biggest reason
//! `busbar-core` failed the deletion test: a neutral crate cannot name a protocol it must be able to
//! ship without. So the ladder became DATA — each protocol states the rungs it claims on its own
//! [`crate::proto::ProtocolDecl::claims`] predicate (a `(headers, path) -> Option<ClaimStrength>`),
//! and [`crate::proto::registry::detect_protocol`] folds those predicates in registration order,
//! keeping the tightest claim. The result is BYTE-IDENTICAL to the old ladder — the claim strengths
//! ARE the ladder positions — but core names no dialect and a build with no protocol plugin simply
//! claims nothing. The per-dialect rungs, and the tests that pin them, live in `busbar-llm`.
//!
//! NB: this is `router` (protocol identification), distinct from `routing` (load-balancing policy).

use axum::http::HeaderMap;

/// The ingress protocol. A thin delegation to the generic detection fold
/// ([`crate::proto::registry::detect_protocol`]) so the one caller (`ingress::dispatch`) keeps its
/// call site; the ladder itself is now the registered protocols' own declared predicates.
pub(crate) fn protocol_id(path: &str, h: &HeaderMap) -> Option<&'static str> {
    crate::proto::registry::detect_protocol(path, h)
}

// NOTE: operation resolution deliberately does NOT live here. The Router identifies the protocol;
// the chosen `RequestHandler::resolve_operation(path, body)` decides the operation (it may need the
// body — Gemini's generateContent and Bedrock's InvokeModel are body-disambiguated).
