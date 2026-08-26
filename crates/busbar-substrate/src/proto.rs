// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral protocol vocabulary relocated DOWN from `busbar-core` (Batch A).
//!
//! These are dependency-free protocol atoms — a wire error-`type` string and the declared inbound
//! auth scheme — that a plane/plugin crate (`busbar-mcp`) names WITHOUT needing `busbar-core`.
//! `busbar-core` re-exports each from its original home (`proto::openai_family` / `proto::registry`)
//! so every existing in-core and plugin caller compiles unchanged. Values are byte-identical to the
//! pre-move definitions.

/// OpenAI error `type` for a missing or invalid API key.
pub const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";

/// WHICH INBOUND AUTH SCHEME a protocol's clients present. DECLARED metadata, never a branch: the
/// verification itself stays in the auth layer, which has the governance key lookup and the shared
/// signing helpers. This replaces `ProtocolReader::uses_sigv4_ingress_auth()`, which was the same
/// fact answered through a vtable — and answering it through a vtable meant allocating a reader to
/// ask a `&'static` question.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngressAuth {
    /// A bearer token / API key in a header (every protocol but Bedrock).
    Bearer,
    /// An AWS SigV4 request signature (Bedrock's ingress shape).
    SigV4,
}
