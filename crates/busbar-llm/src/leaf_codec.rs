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

use crate::ir::audio::{SpeechReq, SpeechResp, TranscriptionReq, TranscriptionResp};
use crate::ir::embeddings::{EmbeddingsReq, EmbeddingsResp};
use crate::ir::image::{ImageReq, ImageResp};
use crate::ir::moderation::{ModerationReq, ModerationResp};
use crate::ir::rerank::{RerankReq, RerankResp};
use busbar_core::handlers::WireBody;
use bytes::Bytes;

/// Embeddings egress request bytes for `proto`. Unknown protocol => `unreachable!` — every caller
/// (dialect handler today, leaf-op handle at A4b) passes a real egress protocol; a future protocol
/// added without extending this match fails LOUDLY here rather than emitting a malformed empty body.
pub(crate) fn embeddings_write_request(proto: &str, r: &EmbeddingsReq) -> Bytes {
    match proto {
        "cohere" => super::cohere::handler::write_embeddings_request(r),
        "bedrock" => super::bedrock::handler::write_embeddings_request(r),
        "gemini" => super::gemini::handler::write_embeddings_request(r),
        "openai" => super::openai_chat::handler::write_embeddings_request(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Embeddings ingress response wire for `proto`. Unknown protocol => `unreachable!` (see the request
/// dispatcher): a missing arm fails loudly, never a malformed empty body.
pub(crate) fn embeddings_write_response(proto: &str, r: &EmbeddingsResp) -> WireBody {
    match proto {
        "cohere" => super::cohere::handler::write_embeddings_response(r),
        "bedrock" => super::bedrock::handler::write_embeddings_response(r),
        "gemini" => super::gemini::handler::write_embeddings_response(r),
        "openai" => super::openai_chat::handler::write_embeddings_response(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Rerank egress request bytes for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn rerank_write_request(proto: &str, r: &RerankReq) -> Bytes {
    match proto {
        "cohere" => super::cohere::handler::write_rerank_request(r),
        "bedrock" => super::bedrock::handler::write_rerank_request(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Rerank ingress response wire for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn rerank_write_response(proto: &str, r: &RerankResp) -> WireBody {
    match proto {
        "cohere" => super::cohere::handler::write_rerank_response(r),
        "bedrock" => super::bedrock::handler::write_rerank_response(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Image egress request bytes for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn image_write_request(proto: &str, r: &ImageReq) -> Bytes {
    match proto {
        "bedrock" => super::bedrock::handler::write_image_request(r),
        "gemini" => super::gemini::handler::write_image_request(r),
        "openai" => super::openai_chat::handler::write_image_request(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Image ingress response wire for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn image_write_response(proto: &str, r: &ImageResp) -> WireBody {
    match proto {
        "bedrock" => super::bedrock::handler::write_image_response(r),
        "gemini" => super::gemini::handler::write_image_response(r),
        "openai" => super::openai_chat::handler::write_image_response(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Transcription egress request bytes for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn transcription_write_request(proto: &str, r: &TranscriptionReq) -> Bytes {
    match proto {
        "gemini" => super::gemini::handler::write_transcription_request(r),
        "openai" => super::openai_chat::handler::write_transcription_request(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Transcription ingress response wire for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn transcription_write_response(proto: &str, r: &TranscriptionResp) -> WireBody {
    match proto {
        "gemini" => super::gemini::handler::write_transcription_response(r),
        "openai" => super::openai_chat::handler::write_transcription_response(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Speech (TTS) egress request bytes for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn speech_write_request(proto: &str, r: &SpeechReq) -> Bytes {
    match proto {
        "gemini" => super::gemini::handler::write_speech_request(r),
        "openai" => super::openai_chat::handler::write_speech_request(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Speech (TTS) ingress response wire for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn speech_write_response(proto: &str, r: &SpeechResp) -> WireBody {
    match proto {
        "gemini" => super::gemini::handler::write_speech_response(r),
        "openai" => super::openai_chat::handler::write_speech_response(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Moderation egress request bytes for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
/// Only openai serves moderation today; the key is uniform with the other ops for the A4b handle.
pub(crate) fn moderation_write_request(proto: &str, r: &ModerationReq) -> Bytes {
    match proto {
        "openai" => super::openai_chat::handler::write_moderation_request(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

/// Moderation ingress response wire for `proto`. Unknown protocol => `unreachable!` (see embeddings dispatcher).
pub(crate) fn moderation_write_response(proto: &str, r: &ModerationResp) -> WireBody {
    match proto {
        "openai" => super::openai_chat::handler::write_moderation_response(r),
        _ => unreachable!("leaf write: unknown egress protocol {proto}"),
    }
}

// ── G6 A4b, owner ruling (b): the (op, protocol) READ dispatch, TEST/`test-support` ONLY ─────────
// Symmetric to the write dispatchers above. Production reads flow through the dialect vtable and the
// `Box<dyn IrHandle>` seam; these expose the SAME concrete parse the trait `read_*` delegates to
// (each dialect's `read_<op>_<dir>` free fn), so a leaf-op fidelity TEST can recover the concrete IR
// keyed by `(op, protocol)` without a downcast (the handle stays sealed). Not compiled in production.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn embeddings_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<crate::ir::embeddings::EmbeddingsReq, busbar_core::handlers::IngressReject> {
    match proto {
        "cohere" => super::cohere::handler::read_embeddings_request(body, content_type),
        "bedrock" => super::bedrock::handler::read_embeddings_request(body, content_type),
        "gemini" => super::gemini::handler::read_embeddings_request(body, content_type),
        "openai" => super::openai_chat::handler::read_embeddings_request(body, content_type),
        other => Err(busbar_core::handlers::IngressReject::BadRequest(format!(
            "no embeddings reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn embeddings_read_response(
    proto: &str,
    wire: &[u8],
) -> Result<crate::ir::embeddings::EmbeddingsResp, busbar_core::handlers::CodecError> {
    match proto {
        "cohere" => super::cohere::handler::read_embeddings_response(wire),
        "bedrock" => super::bedrock::handler::read_embeddings_response(wire),
        "gemini" => super::gemini::handler::read_embeddings_response(wire),
        "openai" => super::openai_chat::handler::read_embeddings_response(wire),
        other => Err(busbar_core::handlers::CodecError::Malformed(format!(
            "no embeddings response reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn rerank_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<crate::ir::rerank::RerankReq, busbar_core::handlers::IngressReject> {
    match proto {
        "cohere" => super::cohere::handler::read_rerank_request(body, content_type),
        "bedrock" => super::bedrock::handler::read_rerank_request(body, content_type),
        other => Err(busbar_core::handlers::IngressReject::BadRequest(format!(
            "no rerank reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn rerank_read_response(
    proto: &str,
    wire: &[u8],
) -> Result<crate::ir::rerank::RerankResp, busbar_core::handlers::CodecError> {
    match proto {
        "cohere" => super::cohere::handler::read_rerank_response(wire),
        "bedrock" => super::bedrock::handler::read_rerank_response(wire),
        other => Err(busbar_core::handlers::CodecError::Malformed(format!(
            "no rerank response reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn image_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<crate::ir::image::ImageReq, busbar_core::handlers::IngressReject> {
    match proto {
        "bedrock" => super::bedrock::handler::read_image_request(body, content_type),
        "gemini" => super::gemini::handler::read_image_request(body, content_type),
        "openai" => super::openai_chat::handler::read_image_request(body, content_type),
        other => Err(busbar_core::handlers::IngressReject::BadRequest(format!(
            "no image reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn image_read_response(
    proto: &str,
    wire: &[u8],
) -> Result<crate::ir::image::ImageResp, busbar_core::handlers::CodecError> {
    match proto {
        "bedrock" => super::bedrock::handler::read_image_response(wire),
        "gemini" => super::gemini::handler::read_image_response(wire),
        "openai" => super::openai_chat::handler::read_image_response(wire),
        other => Err(busbar_core::handlers::CodecError::Malformed(format!(
            "no image response reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn transcription_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<crate::ir::audio::TranscriptionReq, busbar_core::handlers::IngressReject> {
    match proto {
        "gemini" => super::gemini::handler::read_transcription_request(body, content_type),
        "openai" => super::openai_chat::handler::read_transcription_request(body, content_type),
        other => Err(busbar_core::handlers::IngressReject::BadRequest(format!(
            "no transcription reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn transcription_read_response(
    proto: &str,
    wire: &[u8],
) -> Result<crate::ir::audio::TranscriptionResp, busbar_core::handlers::CodecError> {
    match proto {
        "gemini" => super::gemini::handler::read_transcription_response(wire),
        "openai" => super::openai_chat::handler::read_transcription_response(wire),
        other => Err(busbar_core::handlers::CodecError::Malformed(format!(
            "no transcription response reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn speech_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<crate::ir::audio::SpeechReq, busbar_core::handlers::IngressReject> {
    match proto {
        "gemini" => super::gemini::handler::read_speech_request(body, content_type),
        "openai" => super::openai_chat::handler::read_speech_request(body, content_type),
        other => Err(busbar_core::handlers::IngressReject::BadRequest(format!(
            "no speech reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn speech_read_response(
    proto: &str,
    wire: &[u8],
) -> Result<crate::ir::audio::SpeechResp, busbar_core::handlers::CodecError> {
    match proto {
        "gemini" => super::gemini::handler::read_speech_response(wire),
        "openai" => super::openai_chat::handler::read_speech_response(wire),
        other => Err(busbar_core::handlers::CodecError::Malformed(format!(
            "no speech response reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn moderation_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<crate::ir::moderation::ModerationReq, busbar_core::handlers::IngressReject> {
    match proto {
        "openai" => super::openai_chat::handler::read_moderation_request(body, content_type),
        other => Err(busbar_core::handlers::IngressReject::BadRequest(format!(
            "no moderation reader for protocol `{other}`"
        ))),
    }
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn moderation_read_response(
    proto: &str,
    wire: &[u8],
) -> Result<crate::ir::moderation::ModerationResp, busbar_core::handlers::CodecError> {
    match proto {
        "openai" => super::openai_chat::handler::read_moderation_response(wire),
        other => Err(busbar_core::handlers::CodecError::Malformed(format!(
            "no moderation response reader for protocol `{other}`"
        ))),
    }
}
