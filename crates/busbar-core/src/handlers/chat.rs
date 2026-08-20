// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Chat as a STANDARD operation — no operation is "more" than another.
//!
//! [`ChatOperation`] is one TYPE with six per-protocol INSTANCES: each protocol's handler file holds
//! its own `static CHAT: ChatOperation = ChatOperation("<proto>")` and returns it from
//! `operation_handler(Operation::CHAT)`. The deletion test is literal: remove a protocol's instance
//! (its registry line) and that protocol's chat 404s through the SAME no-handler path as any missing
//! operation, while its other operations — and every other protocol — keep working.
//!
//! The codecs are REAL (wire ↔ `IrReq::Chat`/`IrResp::Chat`), delegating to the protocol's
//! `proto::ProtocolReader`/`ProtocolWriter` — the same relationship an embeddings codec has to
//! `serde_json`: the vtable is chat's parser, the OperationHandler owns the operation. Chat's
//! STREAMING translation additionally rides the stream-event machinery those same vtables provide
//! (`read_response_events`/`write_response_event`), reached through the engine only after the
//! dispatch has resolved THIS handler.

use crate::handlers::{CodecError, IngressReject, OperationHandler, WireBody};
use crate::ir::variant::{IrReq, IrResp};
use crate::proto::ProtocolWriter;
use bytes::Bytes;
use serde_json::Value;

/// A protocol's chat operation. The field names the protocol whose `proto::` reader/writer are this
/// instance's codec (resolved per call — `protocol_for` is a static match, no allocation).
pub struct ChatOperation(pub &'static str);

impl ChatOperation {
    fn proto(&self) -> Option<crate::proto::Protocol> {
        crate::proto::protocol_for(self.0)
    }
}

impl OperationHandler for ChatOperation {
    // ---- capabilities (verbatim from the former shared handler / OpSpec) ----

    /// DELEGATED, so no behaviour moves. Chat's error vocabulary is per-protocol and already lives
    /// on `proto::ProtocolReader` — six implementations that know their upstream's error shape —
    /// and the envelope is the PROTOCOL's, read the same way by every operation it serves. So this
    /// and its protocol's non-chat cells all answer through `crate::handlers::protocol_error`, and
    /// chat keeps reporting exactly what it always did now that the breaker asks the cell.
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError {
        crate::handlers::protocol_error(self.0, status, body)
    }

    fn streaming(&self) -> bool {
        true
    }
    fn taps_usage(&self) -> bool {
        true
    }
    fn wants_stream(&self, body: &Value) -> bool {
        // The caller's stream intent from the body (`stream` boolean — openai-family/anthropic/
        // cohere). Path-signaled dialects (gemini `:streamGenerateContent`, bedrock
        // `/converse-stream`) are resolved by their routing arms before this is consulted.
        body.get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false)
    }
    fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        // Top-level `system` string as the body-derived affinity key (no header present). Empty
        // strings do not pin affinity.
        body.get("system")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }
    fn extract_usage(
        &self,
        ingress_protocol: &str,
        body: &[u8],
    ) -> Option<crate::billing::TokenUsage> {
        // Same-protocol usage tap: run the egress (== ingress) reader over the reassembled body.
        // Three distinct failure points (unknown protocol / bad JSON / decode failure) — each is
        // logged at its own site so a same-protocol 2xx body that fails to decode is never a
        // silent 0-tokens bill (mirrors the default `OperationHandler::extract_usage`'s
        // diagnostic, which chat would otherwise lose by overriding it).
        let Some(p) = crate::proto::protocol_for(ingress_protocol) else {
            tracing::warn!(
                protocol = ingress_protocol,
                "usage tap: unknown ingress protocol for a same-protocol 2xx body; \
                 billing 0 tokens for this request"
            );
            return None;
        };
        let v = match crate::json::parse::<Value>(body) {
            Ok(v) => v,
            Err(_e) => {
                // Never log the raw sonic-rs `Display`/`Debug` here — it embeds a fragment of the
                // offending body, which can carry secrets/PII (see `crate::json::parse_err_log`'s
                // doc comment and every other `crate::json::parse` call site in this crate).
                tracing::warn!(
                    error = %crate::json::parse_err_log(body.len()),
                    "usage tap: failed to parse a same-protocol 2xx body as JSON; \
                     billing 0 tokens for this request"
                );
                return None;
            }
        };
        match p.reader().read_response(&v) {
            // The dialect reader still yields the concrete `IrResponse` (that codec RELOCATEs to
            // busbar-llm at the cutover); project its usage into the neutral token totals here so the
            // seam's return names no concrete IR.
            Ok(ir) => Some(ir.usage.to_token_usage()),
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "usage tap: read_response failed to decode a same-protocol 2xx body; \
                     billing 0 tokens for this request"
                );
                None
            }
        }
    }
    fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        writer.egress_accept(wants_stream)
    }

    /// FAIL-CLOSED guard for a cross-protocol chat request whose stop-sequence list exceeds the
    /// egress dialect's published cap (`ProtocolWriter::stop_sequence_cap`, e.g. Cohere's 5).
    /// REJECTS with a reason naming the vendor and the cap rather than proceeding to
    /// `write_request`, which would otherwise silently truncate and forward a WEAKER, DIFFERENT
    /// instruction than the caller gave: a user relying on their Nth+ stop sequence to bound
    /// generation would silently lose that guard. The correct set is small, so the caller can
    /// trivially resubmit within the limit — reject, don't drop-whole.
    fn egress_representable(&self, ir: &IrReq) -> Result<(), String> {
        let IrReq::Chat(r) = ir else { return Ok(()) };
        let Some(p) = self.proto() else { return Ok(()) };
        if let Some((cap, name)) = p.writer().stop_sequence_cap() {
            let provided = r.stop.len();
            if provided > cap {
                return Err(format!(
                    "{name} accepts at most {cap} stop sequences; {provided} provided"
                ));
            }
        }
        Ok(())
    }

    /// The caller controls the egress writer will DROP on cross-protocol translation (e.g.
    /// `response_format`, `tool_choice=none`) — surfaced from the writer vtable so the seam can emit
    /// a first-class audit event per drop. Audit-and-allow: never rejects (unlike
    /// `egress_representable`); the request still forwards.
    fn egress_dropped_controls(&self, ir: &IrReq) -> Vec<&'static str> {
        let IrReq::Chat(r) = ir else {
            return Vec::new();
        };
        let Some(p) = self.proto() else {
            return Vec::new();
        };
        p.writer().dropped_egress_controls(r)
    }

    // ---- Value-level bridges: direct vtable calls (the engine seams hold parsed JSON) ----

    fn read_request_value(&self, v: &Value) -> Result<IrReq, IngressReject> {
        let p = self
            .proto()
            .ok_or_else(|| IngressReject::BadRequest(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_request(v)
            .map(IrReq::Chat)
            .map_err(|e| IngressReject::BadRequest(format!("{e:?}")))
    }
    fn write_request_value(&self, ir: &IrReq) -> Option<Value> {
        let IrReq::Chat(r) = ir else { return None };
        Some(self.proto()?.writer().write_request(r))
    }
    fn read_response_value(&self, v: &Value) -> Result<IrResp, CodecError> {
        let p = self
            .proto()
            .ok_or_else(|| CodecError::Malformed(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_response(v)
            .map(IrResp::Chat)
            .map_err(|e| CodecError::Malformed(format!("{e:?}")))
    }
    fn write_response_value(&self, ir: &IrResp) -> Option<Value> {
        let IrResp::Chat(r) = ir else { return None };
        Some(self.proto()?.writer().write_response(r))
    }

    // ---- codecs: REAL — this protocol's chat wire ↔ the chat IR ----

    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let p = self
            .proto()
            .ok_or_else(|| IngressReject::BadRequest(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_request(&v)
            .map(IrReq::Chat)
            .map_err(|e| IngressReject::BadRequest(format!("{e:?}")))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Chat(r) = ir else {
            return Bytes::new();
        };
        let Some(p) = self.proto() else {
            return Bytes::new();
        };
        Bytes::from(serde_json::to_vec(&p.writer().write_request(r)).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let p = self
            .proto()
            .ok_or_else(|| CodecError::Malformed(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_response(&v)
            .map(IrResp::Chat)
            .map_err(|e| CodecError::Malformed(format!("{e:?}")))
    }
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Chat(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let Some(p) = self.proto() else {
            return WireBody::json(Bytes::new());
        };
        WireBody::json(Bytes::from(
            serde_json::to_vec(&p.writer().write_response(r)).unwrap_or_default(),
        ))
    }
}

#[cfg(test)]
#[path = "tests/chat_tests.rs"]
mod tests;
