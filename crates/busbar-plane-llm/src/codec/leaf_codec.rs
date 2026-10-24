// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **G6 A4b, option (a) — the per-`(operation, egress-protocol)` LEAF-OP writer dispatch.**
//!
//! The chat operation already selects its writer by egress-protocol string
//! (`proto_codec::protocol_for(proto).writer()`); the six non-chat leaf ops
//! (embeddings/image/rerank/transcription/speech/moderation) did not — each dialect's write body
//! lived inline in its `OperationHandler::{write_request,write_response}`, reachable only by holding
//! that dialect's handler instance. That is exactly the coupling the A4b dissolve cannot cross without
//! a `Box<dyn Any>` downcast (owner-forbidden): once `IrReq`/`IrResp` dissolve onto `Box<dyn IrHandle>`
//! a leaf-op handle cannot pattern-match its way back to `&EmbeddingsReq` to feed the egress writer.
//!
//! So — mirroring chat — each leaf op gets a writer selected by `(operation, egress-protocol)` KEY:
//! the per-dialect write body is a free fn in that dialect's `handler` module, and the dialect
//! DECLARES which ops it speaks as data — its [`LeafCodecs`] row, carried on its registration
//! ([`crate::codec::proto_codec::DialectEntry::leaf`]). The dispatchers below find the egress
//! dialect's row by name and call the fn it declared; no dispatcher names a dialect (design F3
//! SELF-CONTAINED: central name-`match` registries become per-dialect registration). Today the dialect `OperationHandler`s
//! route their own writes through these (byte-identical — same bytes out, same order); at A4b the
//! leaf-op `IrHandle::write_egress_request` calls the SAME dispatcher keyed by the egress protocol, so
//! the write no longer needs the concrete enum. Prep only: names no `IrReq`/`IrResp`, moves no bytes.

use crate::codec::ir::audio::{SpeechReq, SpeechResp, TranscriptionReq, TranscriptionResp};
use crate::codec::ir::embeddings::{EmbeddingsReq, EmbeddingsResp};
use crate::codec::ir::image::{ImageReq, ImageResp};
use crate::codec::ir::moderation::{ModerationReq, ModerationResp};
use crate::codec::ir::rerank::{RerankReq, RerankResp};
use busbar_contract::codec::{CodecError, IngressReject, WireBody};
use bytes::Bytes;

/// ONE LEAF OPERATION'S FOUR CODEC FNS in one dialect: the egress request writer, the ingress
/// response writer, and the two concrete reads (the reads the dialect's `OperationHandler` wraps in
/// a leaf handle; the `(op, protocol)` read dispatch below reaches them in test builds).
pub struct LeafCodec<Q: 'static, A: 'static> {
    pub write_request: fn(&Q) -> Bytes,
    pub write_response: fn(&A) -> WireBody,
    pub read_request: fn(&[u8], &str) -> Result<Q, IngressReject>,
    pub read_response: fn(&[u8]) -> Result<A, CodecError>,
}

/// A DIALECT'S ROW OF THE LEAF-OP SUPPORT MATRIX, as data: `Some` for each leaf op the dialect
/// speaks, `None` for the rest. Declared once in the dialect's own `handler` module.
pub struct LeafCodecs {
    pub embeddings: Option<LeafCodec<EmbeddingsReq, EmbeddingsResp>>,
    pub rerank: Option<LeafCodec<RerankReq, RerankResp>>,
    pub image: Option<LeafCodec<ImageReq, ImageResp>>,
    pub transcription: Option<LeafCodec<TranscriptionReq, TranscriptionResp>>,
    pub speech: Option<LeafCodec<SpeechReq, SpeechResp>>,
    pub moderation: Option<LeafCodec<ModerationReq, ModerationResp>>,
}

impl LeafCodecs {
    /// The row of a dialect that speaks no leaf op (chat only).
    pub const NONE: Self = Self {
        embeddings: None,
        rerank: None,
        image: None,
        transcription: None,
        speech: None,
        moderation: None,
    };
}

/// The `(operation, protocol)` cell: the named dialect's declared codec for the op `pick` selects.
/// `None` when no dialect has that name, or it declares no codec for the op.
fn cell<Q, A>(
    proto: &str,
    pick: fn(&'static LeafCodecs) -> Option<&'static LeafCodec<Q, A>>,
) -> Option<&'static LeafCodec<Q, A>> {
    crate::codec::proto_codec::entry_of(proto).and_then(|d| pick(d.leaf))
}

/// The write cell for `proto`. Unknown protocol (or one that does not speak the op) =>
/// `unreachable!` — every caller (dialect handler, leaf-op handle) passes a real egress protocol for
/// an op it routed there; a protocol added without declaring the op fails LOUDLY here rather than
/// emitting a malformed empty body.
fn write_cell<Q, A>(
    proto: &str,
    pick: fn(&'static LeafCodecs) -> Option<&'static LeafCodec<Q, A>>,
) -> &'static LeafCodec<Q, A> {
    cell(proto, pick).unwrap_or_else(|| unreachable!("leaf write: unknown egress protocol {proto}"))
}

/// Embeddings egress request bytes for `proto` (see [`write_cell`] for an unknown protocol).
pub fn embeddings_write_request(proto: &str, r: &EmbeddingsReq) -> Bytes {
    (write_cell(proto, |l| l.embeddings.as_ref()).write_request)(r)
}

/// Embeddings ingress response wire for `proto` (see [`write_cell`] for an unknown protocol).
pub fn embeddings_write_response(proto: &str, r: &EmbeddingsResp) -> WireBody {
    (write_cell(proto, |l| l.embeddings.as_ref()).write_response)(r)
}

/// Rerank egress request bytes for `proto` (see [`write_cell`] for an unknown protocol).
pub fn rerank_write_request(proto: &str, r: &RerankReq) -> Bytes {
    (write_cell(proto, |l| l.rerank.as_ref()).write_request)(r)
}

/// Rerank ingress response wire for `proto` (see [`write_cell`] for an unknown protocol).
pub fn rerank_write_response(proto: &str, r: &RerankResp) -> WireBody {
    (write_cell(proto, |l| l.rerank.as_ref()).write_response)(r)
}

/// Image egress request bytes for `proto` (see [`write_cell`] for an unknown protocol).
pub fn image_write_request(proto: &str, r: &ImageReq) -> Bytes {
    (write_cell(proto, |l| l.image.as_ref()).write_request)(r)
}

/// Image ingress response wire for `proto` (see [`write_cell`] for an unknown protocol).
pub fn image_write_response(proto: &str, r: &ImageResp) -> WireBody {
    (write_cell(proto, |l| l.image.as_ref()).write_response)(r)
}

/// Transcription egress request bytes for `proto` (see [`write_cell`] for an unknown protocol).
pub fn transcription_write_request(proto: &str, r: &TranscriptionReq) -> Bytes {
    (write_cell(proto, |l| l.transcription.as_ref()).write_request)(r)
}

/// Transcription ingress response wire for `proto` (see [`write_cell`] for an unknown protocol).
pub fn transcription_write_response(proto: &str, r: &TranscriptionResp) -> WireBody {
    (write_cell(proto, |l| l.transcription.as_ref()).write_response)(r)
}

/// Speech (TTS) egress request bytes for `proto` (see [`write_cell`] for an unknown protocol).
pub fn speech_write_request(proto: &str, r: &SpeechReq) -> Bytes {
    (write_cell(proto, |l| l.speech.as_ref()).write_request)(r)
}

/// Speech (TTS) ingress response wire for `proto` (see [`write_cell`] for an unknown protocol).
pub fn speech_write_response(proto: &str, r: &SpeechResp) -> WireBody {
    (write_cell(proto, |l| l.speech.as_ref()).write_response)(r)
}

/// Moderation egress request bytes for `proto` (see [`write_cell`] for an unknown protocol).
pub fn moderation_write_request(proto: &str, r: &ModerationReq) -> Bytes {
    (write_cell(proto, |l| l.moderation.as_ref()).write_request)(r)
}

/// Moderation ingress response wire for `proto` (see [`write_cell`] for an unknown protocol).
pub fn moderation_write_response(proto: &str, r: &ModerationResp) -> WireBody {
    (write_cell(proto, |l| l.moderation.as_ref()).write_response)(r)
}

// ── G6 A4b, owner ruling (b): the (op, protocol) READ dispatch, TEST/`test-support` ONLY ─────────
// Symmetric to the write dispatchers above. Production reads flow through the dialect vtable and the
// `Box<dyn IrHandle>` seam; these expose the SAME concrete parse the trait `read_*` delegates to
// (each dialect's `read_<op>_<dir>` free fn, as its `LeafCodecs` row declares it), so a leaf-op
// fidelity TEST can recover the concrete IR keyed by `(op, protocol)` without a downcast (the handle
// stays sealed). Not compiled in production.

/// The request read for `(op, proto)`; a protocol with no reader for the op is a `BadRequest`.
#[cfg(any(test, feature = "test-support"))]
fn read_request<Q, A>(
    op: &str,
    proto: &str,
    pick: fn(&'static LeafCodecs) -> Option<&'static LeafCodec<Q, A>>,
    body: &[u8],
    content_type: &str,
) -> Result<Q, IngressReject> {
    match cell(proto, pick) {
        Some(c) => (c.read_request)(body, content_type),
        None => Err(IngressReject::BadRequest(format!(
            "no {op} reader for protocol `{proto}`"
        ))),
    }
}

/// The response read for `(op, proto)`; a protocol with no reader for the op is `Malformed`.
#[cfg(any(test, feature = "test-support"))]
fn read_response<Q, A>(
    op: &str,
    proto: &str,
    pick: fn(&'static LeafCodecs) -> Option<&'static LeafCodec<Q, A>>,
    wire: &[u8],
) -> Result<A, CodecError> {
    match cell(proto, pick) {
        Some(c) => (c.read_response)(wire),
        None => Err(CodecError::Malformed(format!(
            "no {op} response reader for protocol `{proto}`"
        ))),
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn embeddings_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<EmbeddingsReq, IngressReject> {
    read_request(
        "embeddings",
        proto,
        |l| l.embeddings.as_ref(),
        body,
        content_type,
    )
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn embeddings_read_response(proto: &str, wire: &[u8]) -> Result<EmbeddingsResp, CodecError> {
    read_response("embeddings", proto, |l| l.embeddings.as_ref(), wire)
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn rerank_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<RerankReq, IngressReject> {
    read_request("rerank", proto, |l| l.rerank.as_ref(), body, content_type)
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn rerank_read_response(proto: &str, wire: &[u8]) -> Result<RerankResp, CodecError> {
    read_response("rerank", proto, |l| l.rerank.as_ref(), wire)
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn image_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<ImageReq, IngressReject> {
    read_request("image", proto, |l| l.image.as_ref(), body, content_type)
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn image_read_response(proto: &str, wire: &[u8]) -> Result<ImageResp, CodecError> {
    read_response("image", proto, |l| l.image.as_ref(), wire)
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn transcription_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<TranscriptionReq, IngressReject> {
    read_request(
        "transcription",
        proto,
        |l| l.transcription.as_ref(),
        body,
        content_type,
    )
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn transcription_read_response(
    proto: &str,
    wire: &[u8],
) -> Result<TranscriptionResp, CodecError> {
    read_response("transcription", proto, |l| l.transcription.as_ref(), wire)
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn speech_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<SpeechReq, IngressReject> {
    read_request("speech", proto, |l| l.speech.as_ref(), body, content_type)
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn speech_read_response(proto: &str, wire: &[u8]) -> Result<SpeechResp, CodecError> {
    read_response("speech", proto, |l| l.speech.as_ref(), wire)
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn moderation_read_request(
    proto: &str,
    body: &[u8],
    content_type: &str,
) -> Result<ModerationReq, IngressReject> {
    read_request(
        "moderation",
        proto,
        |l| l.moderation.as_ref(),
        body,
        content_type,
    )
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub fn moderation_read_response(proto: &str, wire: &[u8]) -> Result<ModerationResp, CodecError> {
    read_response("moderation", proto, |l| l.moderation.as_ref(), wire)
}
