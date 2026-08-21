// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **G6 A4b, option (a) — the per-`(operation, egress-protocol)` LEAF-OP writer dispatch.**
//!
//! The chat operation already selects its writer by egress-protocol string
//! (`busbar_core::proto::protocol_for(proto).writer()`); the six non-chat leaf ops
//! (embeddings/image/rerank/transcription/speech/moderation) did not — each dialect's write body
//! lived inline in its `OperationHandler::{write_request,write_response}`, reachable only by holding
//! that dialect's handler instance. That is exactly the coupling the A4b dissolve cannot cross without
//! a `Box<dyn Any>` downcast (owner-forbidden): once `IrReq`/`IrResp` dissolve onto `Box<dyn IrHandle>`
//! a leaf-op handle cannot pattern-match its way back to `&EmbeddingsReq` to feed the egress writer.
//!
//! So — mirroring chat — each leaf op gets a writer selected by `(operation, egress-protocol)` KEY:
//! the per-dialect write body moves to a `pub(crate)` free fn in that dialect's `handler` module, and
//! the dispatchers below map the egress-protocol string to it. Today the dialect `OperationHandler`s
//! route their own writes through these (byte-identical — same bytes out, same order); at A4b the
//! leaf-op `IrHandle::write_egress_request` calls the SAME dispatcher keyed by the egress protocol, so
//! the write no longer needs the concrete enum. Prep only: names no `IrReq`/`IrResp`, moves no bytes.

use busbar_core::handlers::WireBody;
use busbar_core::ir::embeddings::{EmbeddingsReq, EmbeddingsResp};
use bytes::Bytes;

/// Embeddings egress request bytes for `proto`. Unknown protocol => empty (the pre-cutover
/// wrong-variant fallback; never reached from a dialect handler, which passes its own protocol).
pub(crate) fn embeddings_write_request(proto: &str, r: &EmbeddingsReq) -> Bytes {
    match proto {
        "cohere" => super::cohere::handler::write_embeddings_request(r),
        "bedrock" => super::bedrock::handler::write_embeddings_request(r),
        "gemini" => super::gemini::handler::write_embeddings_request(r),
        "openai" => super::openai_chat::handler::write_embeddings_request(r),
        _ => Bytes::new(),
    }
}

/// Embeddings ingress response wire for `proto`. Unknown protocol => empty JSON body (the pre-cutover
/// wrong-variant fallback).
pub(crate) fn embeddings_write_response(proto: &str, r: &EmbeddingsResp) -> WireBody {
    match proto {
        "cohere" => super::cohere::handler::write_embeddings_response(r),
        "bedrock" => super::bedrock::handler::write_embeddings_response(r),
        "gemini" => super::gemini::handler::write_embeddings_response(r),
        "openai" => super::openai_chat::handler::write_embeddings_response(r),
        _ => WireBody::json(Bytes::new()),
    }
}
