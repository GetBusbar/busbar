// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The six leaf-op `IrHandle`s (G6 A4b dissolve): embeddings / image / rerank / moderation /
//! transcription / speech. Each wraps its concrete `crate::ir::*` request/response and writes itself
//! onto the peer dialect by protocol string via the `(op, protocol)` `leaf_codec` dispatchers
//! (option-a). The prep arms are all no-ops (leaf ops carry no cross-protocol reshape); `set_model`
//! stamps the model; billing projects each op's own usage. Uniform: the write methods reproduce the
//! former default `write_request_value`/`write_response_value` (JSON-parse the leaf bytes, else the
//! opaque `Bytes`/`Typed` fall-through) — byte-identical to the dissolved `IrReq`/`IrResp` arms.

use crate::ir::audio::{SpeechReq, SpeechResp, TranscriptionReq, TranscriptionResp};
use crate::ir::embeddings::{EmbeddingsReq, EmbeddingsResp};
use crate::ir::image::{ImageReq, ImageResp};
use crate::ir::moderation::{ModerationReq, ModerationResp};
use crate::ir::rerank::{RerankReq, RerankResp};
use busbar_api::operation::Operation;
use busbar_substrate::billing::Billing;
use busbar_substrate::ir::facts::IrFacts;
use busbar_substrate::ir::handle::sealed::Sealed;
use busbar_substrate::ir::handle::IrHandle;
use busbar_substrate::wire::{EgressWire, TranslatedResponse};
use bytes::Bytes;
use serde_json::Value;

// ─────────────────────────────── embeddings ───────────────────────────────
pub struct EmbeddingsReqHandle(pub EmbeddingsReq);
pub struct EmbeddingsRespHandle(pub EmbeddingsResp);
impl Sealed for EmbeddingsReqHandle {}
impl Sealed for EmbeddingsRespHandle {}

impl IrHandle for EmbeddingsReqHandle {
    fn verb(&self) -> Operation {
        Operation::EMBEDDINGS
    }
    fn wants_stream(&self) -> bool {
        false
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
    fn set_model(&mut self, model: &str) {
        self.0.model = model.to_string();
    }
    fn write_egress_request(&mut self, egress_proto: &str, model: &str) -> EgressWire {
        let bytes = super::leaf_codec::embeddings_write_request(egress_proto, &self.0);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => EgressWire::Json(v),
            Err(_) => {
                self.0.model = model.to_string();
                EgressWire::Bytes(super::leaf_codec::embeddings_write_request(
                    egress_proto,
                    &self.0,
                ))
            }
        }
    }
    fn write_egress_request_bytes(&mut self, egress_proto: &str, model: &str) -> Bytes {
        self.0.model = model.to_string();
        super::leaf_codec::embeddings_write_request(egress_proto, &self.0)
    }
}

impl IrHandle for EmbeddingsRespHandle {
    fn verb(&self) -> Operation {
        Operation::EMBEDDINGS
    }
    fn billing(&self) -> Option<Billing> {
        self.0.billing()
    }
    fn write_ingress_response(&self, ingress_proto: &str, serves_op: bool) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::IngressUnsupported;
        }
        let wb = super::leaf_codec::embeddings_write_response(ingress_proto, &self.0);
        match serde_json::from_slice::<Value>(&wb.bytes) {
            Ok(v) => TranslatedResponse::Json(v),
            Err(_) => TranslatedResponse::Typed(wb),
        }
    }
    fn write_ingress_response_bytes(
        &self,
        ingress_proto: &str,
        serves_op: bool,
    ) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::Untranslatable;
        }
        TranslatedResponse::Typed(super::leaf_codec::embeddings_write_response(
            ingress_proto,
            &self.0,
        ))
    }
}

// ─────────────────────────────── image ───────────────────────────────
pub struct ImageReqHandle(pub ImageReq);
pub struct ImageRespHandle(pub ImageResp);
impl Sealed for ImageReqHandle {}
impl Sealed for ImageRespHandle {}

impl IrHandle for ImageReqHandle {
    fn verb(&self) -> Operation {
        Operation::IMAGE
    }
    fn wants_stream(&self) -> bool {
        false
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
    fn set_model(&mut self, model: &str) {
        self.0.model = model.to_string();
    }
    fn write_egress_request(&mut self, egress_proto: &str, model: &str) -> EgressWire {
        let bytes = super::leaf_codec::image_write_request(egress_proto, &self.0);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => EgressWire::Json(v),
            Err(_) => {
                self.0.model = model.to_string();
                EgressWire::Bytes(super::leaf_codec::image_write_request(
                    egress_proto,
                    &self.0,
                ))
            }
        }
    }
    fn write_egress_request_bytes(&mut self, egress_proto: &str, model: &str) -> Bytes {
        self.0.model = model.to_string();
        super::leaf_codec::image_write_request(egress_proto, &self.0)
    }
}

impl IrHandle for ImageRespHandle {
    fn verb(&self) -> Operation {
        Operation::IMAGE
    }
    fn billing(&self) -> Option<Billing> {
        self.0.billing()
    }
    fn write_ingress_response(&self, ingress_proto: &str, serves_op: bool) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::IngressUnsupported;
        }
        let wb = super::leaf_codec::image_write_response(ingress_proto, &self.0);
        match serde_json::from_slice::<Value>(&wb.bytes) {
            Ok(v) => TranslatedResponse::Json(v),
            Err(_) => TranslatedResponse::Typed(wb),
        }
    }
    fn write_ingress_response_bytes(
        &self,
        ingress_proto: &str,
        serves_op: bool,
    ) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::Untranslatable;
        }
        TranslatedResponse::Typed(super::leaf_codec::image_write_response(
            ingress_proto,
            &self.0,
        ))
    }
}

// ─────────────────────────────── rerank ───────────────────────────────
pub struct RerankReqHandle(pub RerankReq);
pub struct RerankRespHandle(pub RerankResp);
impl Sealed for RerankReqHandle {}
impl Sealed for RerankRespHandle {}

impl IrHandle for RerankReqHandle {
    fn verb(&self) -> Operation {
        Operation::RERANK
    }
    fn wants_stream(&self) -> bool {
        false
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
    fn set_model(&mut self, model: &str) {
        self.0.model = model.to_string();
    }
    fn write_egress_request(&mut self, egress_proto: &str, model: &str) -> EgressWire {
        let bytes = super::leaf_codec::rerank_write_request(egress_proto, &self.0);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => EgressWire::Json(v),
            Err(_) => {
                self.0.model = model.to_string();
                EgressWire::Bytes(super::leaf_codec::rerank_write_request(
                    egress_proto,
                    &self.0,
                ))
            }
        }
    }
    fn write_egress_request_bytes(&mut self, egress_proto: &str, model: &str) -> Bytes {
        self.0.model = model.to_string();
        super::leaf_codec::rerank_write_request(egress_proto, &self.0)
    }
}

impl IrHandle for RerankRespHandle {
    fn verb(&self) -> Operation {
        Operation::RERANK
    }
    fn billing(&self) -> Option<Billing> {
        self.0.billing()
    }
    fn write_ingress_response(&self, ingress_proto: &str, serves_op: bool) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::IngressUnsupported;
        }
        let wb = super::leaf_codec::rerank_write_response(ingress_proto, &self.0);
        match serde_json::from_slice::<Value>(&wb.bytes) {
            Ok(v) => TranslatedResponse::Json(v),
            Err(_) => TranslatedResponse::Typed(wb),
        }
    }
    fn write_ingress_response_bytes(
        &self,
        ingress_proto: &str,
        serves_op: bool,
    ) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::Untranslatable;
        }
        TranslatedResponse::Typed(super::leaf_codec::rerank_write_response(
            ingress_proto,
            &self.0,
        ))
    }
}

// ─────────────────────────────── moderation ───────────────────────────────
pub struct ModerationReqHandle(pub ModerationReq);
pub struct ModerationRespHandle(pub ModerationResp);
impl Sealed for ModerationReqHandle {}
impl Sealed for ModerationRespHandle {}

impl IrHandle for ModerationReqHandle {
    fn verb(&self) -> Operation {
        Operation::MODERATION
    }
    fn wants_stream(&self) -> bool {
        false
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
    fn set_model(&mut self, model: &str) {
        self.0.model = model.to_string();
    }
    fn write_egress_request(&mut self, egress_proto: &str, model: &str) -> EgressWire {
        let bytes = super::leaf_codec::moderation_write_request(egress_proto, &self.0);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => EgressWire::Json(v),
            Err(_) => {
                self.0.model = model.to_string();
                EgressWire::Bytes(super::leaf_codec::moderation_write_request(
                    egress_proto,
                    &self.0,
                ))
            }
        }
    }
    fn write_egress_request_bytes(&mut self, egress_proto: &str, model: &str) -> Bytes {
        self.0.model = model.to_string();
        super::leaf_codec::moderation_write_request(egress_proto, &self.0)
    }
}

impl IrHandle for ModerationRespHandle {
    fn verb(&self) -> Operation {
        Operation::MODERATION
    }
    fn billing(&self) -> Option<Billing> {
        Some(Billing::Flat)
    }
    fn write_ingress_response(&self, ingress_proto: &str, serves_op: bool) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::IngressUnsupported;
        }
        let wb = super::leaf_codec::moderation_write_response(ingress_proto, &self.0);
        match serde_json::from_slice::<Value>(&wb.bytes) {
            Ok(v) => TranslatedResponse::Json(v),
            Err(_) => TranslatedResponse::Typed(wb),
        }
    }
    fn write_ingress_response_bytes(
        &self,
        ingress_proto: &str,
        serves_op: bool,
    ) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::Untranslatable;
        }
        TranslatedResponse::Typed(super::leaf_codec::moderation_write_response(
            ingress_proto,
            &self.0,
        ))
    }
}

// ─────────────────────────────── transcription ───────────────────────────────
pub struct TranscriptionReqHandle(pub TranscriptionReq);
pub struct TranscriptionRespHandle(pub TranscriptionResp);
impl Sealed for TranscriptionReqHandle {}
impl Sealed for TranscriptionRespHandle {}

impl IrHandle for TranscriptionReqHandle {
    fn verb(&self) -> Operation {
        Operation::TRANSCRIPTION
    }
    fn wants_stream(&self) -> bool {
        self.0.stream
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
    fn set_model(&mut self, model: &str) {
        self.0.model = model.to_string();
    }
    fn write_egress_request(&mut self, egress_proto: &str, model: &str) -> EgressWire {
        let bytes = super::leaf_codec::transcription_write_request(egress_proto, &self.0);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => EgressWire::Json(v),
            Err(_) => {
                self.0.model = model.to_string();
                EgressWire::Bytes(super::leaf_codec::transcription_write_request(
                    egress_proto,
                    &self.0,
                ))
            }
        }
    }
    fn write_egress_request_bytes(&mut self, egress_proto: &str, model: &str) -> Bytes {
        self.0.model = model.to_string();
        super::leaf_codec::transcription_write_request(egress_proto, &self.0)
    }
}

impl IrHandle for TranscriptionRespHandle {
    fn verb(&self) -> Operation {
        Operation::TRANSCRIPTION
    }
    fn billing(&self) -> Option<Billing> {
        self.0.billing()
    }
    fn write_ingress_response(&self, ingress_proto: &str, serves_op: bool) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::IngressUnsupported;
        }
        let wb = super::leaf_codec::transcription_write_response(ingress_proto, &self.0);
        match serde_json::from_slice::<Value>(&wb.bytes) {
            Ok(v) => TranslatedResponse::Json(v),
            Err(_) => TranslatedResponse::Typed(wb),
        }
    }
    fn write_ingress_response_bytes(
        &self,
        ingress_proto: &str,
        serves_op: bool,
    ) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::Untranslatable;
        }
        TranslatedResponse::Typed(super::leaf_codec::transcription_write_response(
            ingress_proto,
            &self.0,
        ))
    }
}

// ─────────────────────────────── speech ───────────────────────────────
pub struct SpeechReqHandle(pub SpeechReq);
pub struct SpeechRespHandle(pub SpeechResp);
impl Sealed for SpeechReqHandle {}
impl Sealed for SpeechRespHandle {}

impl IrHandle for SpeechReqHandle {
    fn verb(&self) -> Operation {
        Operation::SPEECH
    }
    fn wants_stream(&self) -> bool {
        self.0.stream
    }
    /// The TTS request-seam meter (see [`SpeechReq::billing`]): the exact character count of the
    /// input, the true billable unit — knowable here, never from the opaque audio response.
    fn billing(&self) -> Option<Billing> {
        self.0.billing()
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
    fn set_model(&mut self, model: &str) {
        self.0.model = model.to_string();
    }
    fn write_egress_request(&mut self, egress_proto: &str, model: &str) -> EgressWire {
        let bytes = super::leaf_codec::speech_write_request(egress_proto, &self.0);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => EgressWire::Json(v),
            Err(_) => {
                self.0.model = model.to_string();
                EgressWire::Bytes(super::leaf_codec::speech_write_request(
                    egress_proto,
                    &self.0,
                ))
            }
        }
    }
    fn write_egress_request_bytes(&mut self, egress_proto: &str, model: &str) -> Bytes {
        self.0.model = model.to_string();
        super::leaf_codec::speech_write_request(egress_proto, &self.0)
    }
}

impl IrHandle for SpeechRespHandle {
    fn verb(&self) -> Operation {
        Operation::SPEECH
    }
    fn billing(&self) -> Option<Billing> {
        self.0.billing()
    }
    fn write_ingress_response(&self, ingress_proto: &str, serves_op: bool) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::IngressUnsupported;
        }
        let wb = super::leaf_codec::speech_write_response(ingress_proto, &self.0);
        match serde_json::from_slice::<Value>(&wb.bytes) {
            Ok(v) => TranslatedResponse::Json(v),
            Err(_) => TranslatedResponse::Typed(wb),
        }
    }
    fn write_ingress_response_bytes(
        &self,
        ingress_proto: &str,
        serves_op: bool,
    ) -> TranslatedResponse {
        if !serves_op {
            return TranslatedResponse::Untranslatable;
        }
        TranslatedResponse::Typed(super::leaf_codec::speech_write_response(
            ingress_proto,
            &self.0,
        ))
    }
}
